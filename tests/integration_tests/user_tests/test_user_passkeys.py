from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pytest import MonkeyPatch
from sqlalchemy import update
from sqlalchemy.orm import Session

from mealie.core.config import get_app_settings
from mealie.db.models.users.passkeys import PasskeyChallenge, UserPasskey
from mealie.db.models.users.users import AuthMethod, User
from mealie.services.user_services.user_service import UserService
from tests.utils import api_routes
from tests.utils.fixture_schemas import TestUser
from tests.utils.passkeys import SoftAuthenticator

RP_ID = "mealie.example.com"
ORIGIN = f"https://{RP_ID}"


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """monkeypatch restores the env vars, but the cached settings object would keep the patched values."""
    yield
    get_app_settings.cache_clear()


@pytest.fixture
def passkeys_enabled(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("PASSKEYS_ENABLED", "true")
    monkeypatch.setenv("BASE_URL", ORIGIN)
    get_app_settings.cache_clear()


@pytest.fixture
def authenticator() -> SoftAuthenticator:
    return SoftAuthenticator(rp_id=RP_ID, origin=ORIGIN)


def registration_options(api_client: TestClient, user: TestUser, password: str | None = None) -> dict:
    response = api_client.post(
        api_routes.users_self_passkeys_registration_options,
        json={"currentPassword": user.password if password is None else password},
        headers=user.token,
    )
    assert response.status_code == 200, response.text
    return response.json()


def add_passkey(
    api_client: TestClient, user: TestUser, authenticator: SoftAuthenticator, name: str = "Test key"
) -> dict:
    started = registration_options(api_client, user)
    response = api_client.post(
        api_routes.users_self_passkeys,
        json={
            "challengeId": started["challengeId"],
            "name": name,
            "credential": authenticator.create(started["options"]),
        },
        headers=user.token,
    )
    assert response.status_code == 201, response.text
    return response.json()


def login_options(api_client: TestClient) -> dict:
    response = api_client.post(api_routes.auth_passkey_options)
    assert response.status_code == 200, response.text
    return response.json()


def passkey_login(api_client: TestClient, challenge_id: str, credential: dict, remember_me: bool = False):
    return api_client.post(
        api_routes.auth_passkey,
        json={"challengeId": challenge_id, "credential": credential, "rememberMe": remember_me},
    )


# ================================================================
# Feature flag


def test_passkey_endpoints_404_when_disabled(api_client: TestClient, unique_user: TestUser):
    assert api_client.post(api_routes.auth_passkey_options).status_code == 404
    assert api_client.post(api_routes.auth_passkey, json={"challengeId": "x", "credential": {}}).status_code in (
        404,
        422,
    )
    response = api_client.post(
        api_routes.users_self_passkeys_registration_options,
        json={"currentPassword": unique_user.password},
        headers=unique_user.token,
    )
    assert response.status_code == 404


def test_passkeys_need_a_secure_base_url(api_client: TestClient, monkeypatch: MonkeyPatch):
    monkeypatch.setenv("PASSKEYS_ENABLED", "true")
    monkeypatch.setenv("BASE_URL", "http://192.168.1.10:9000")
    get_app_settings.cache_clear()

    assert api_client.post(api_routes.auth_passkey_options).status_code == 404
    assert api_client.get(api_routes.app_about).json()["enablePasskeys"] is False


def test_about_reports_passkeys(api_client: TestClient, passkeys_enabled):
    assert api_client.get(api_routes.app_about).json()["enablePasskeys"] is True


# ================================================================
# Adding passkeys


def test_registration_options(api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser):
    options = registration_options(api_client, unique_user_fn_scoped)["options"]

    assert options["rp"]["id"] == RP_ID
    assert options["user"]["name"] == unique_user_fn_scoped.email
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["excludeCredentials"] == []


def test_registration_needs_the_current_password(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser
):
    response = api_client.post(
        api_routes.users_self_passkeys_registration_options,
        json={"currentPassword": "not-the-password"},
        headers=unique_user_fn_scoped.token,
    )
    assert response.status_code == 400


def test_add_list_and_delete_passkey(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    user = unique_user_fn_scoped
    created = add_passkey(api_client, user, authenticator, name="  Work laptop  ")
    assert created["name"] == "Work laptop"
    assert created["backedUp"] is True
    assert created["lastUsedAt"] is None
    # Nothing the browser doesn't need leaves the server
    assert "publicKey" not in created
    assert "credentialId" not in created

    listed = api_client.get(api_routes.users_self_passkeys, headers=user.token).json()
    assert [p["id"] for p in listed] == [created["id"]]

    # The authenticator that already has a passkey is excluded from the next registration
    options = registration_options(api_client, user)["options"]
    assert [c["id"] for c in options["excludeCredentials"]] == [authenticator.create(options)["id"]]

    response = api_client.delete(api_routes.users_self_passkeys_passkey_id(created["id"]), headers=user.token)
    assert response.status_code == 200
    assert api_client.get(api_routes.users_self_passkeys, headers=user.token).json() == []


def test_cannot_delete_someone_elses_passkey(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    unique_user: TestUser,
    authenticator: SoftAuthenticator,
):
    created = add_passkey(api_client, unique_user_fn_scoped, authenticator)

    response = api_client.delete(api_routes.users_self_passkeys_passkey_id(created["id"]), headers=unique_user.token)
    assert response.status_code == 404
    assert len(api_client.get(api_routes.users_self_passkeys, headers=unique_user_fn_scoped.token).json()) == 1


def test_registration_challenge_is_bound_to_the_user(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    unique_user: TestUser,
    authenticator: SoftAuthenticator,
):
    started = registration_options(api_client, unique_user_fn_scoped)

    response = api_client.post(
        api_routes.users_self_passkeys,
        json={
            "challengeId": started["challengeId"],
            "name": "Not mine",
            "credential": authenticator.create(started["options"]),
        },
        headers=unique_user.token,
    )
    assert response.status_code == 400


def test_registration_challenge_is_single_use(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    user = unique_user_fn_scoped
    started = registration_options(api_client, user)
    body = {
        "challengeId": started["challengeId"],
        "name": "Key",
        "credential": authenticator.create(started["options"]),
    }

    assert api_client.post(api_routes.users_self_passkeys, json=body, headers=user.token).status_code == 201
    assert api_client.post(api_routes.users_self_passkeys, json=body, headers=user.token).status_code == 400


@pytest.mark.parametrize(
    "fault",
    ["wrong_origin", "no_user_verification", "garbage", "sign_in_challenge"],
)
def test_bad_registration_is_rejected(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    authenticator: SoftAuthenticator,
    fault: str,
):
    user = unique_user_fn_scoped
    started = registration_options(api_client, user)
    challenge_id = started["challengeId"]

    if fault == "wrong_origin":
        credential = authenticator.create(started["options"], origin="https://evil.example.com")
    elif fault == "no_user_verification":
        authenticator.user_verification = False
        credential = authenticator.create(started["options"])
    elif fault == "garbage":
        credential = {"id": "nope", "response": {"clientDataJSON": "!!"}}
    else:
        # a sign-in challenge can't be redeemed to add a passkey
        login = login_options(api_client)
        challenge_id = login["challengeId"]
        credential = authenticator.create({**started["options"], "challenge": login["options"]["challenge"]})

    response = api_client.post(
        api_routes.users_self_passkeys,
        json={"challengeId": challenge_id, "name": "Key", "credential": credential},
        headers=user.token,
    )
    assert response.status_code == 400
    assert api_client.get(api_routes.users_self_passkeys, headers=user.token).json() == []


def test_same_passkey_cannot_be_registered_twice(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    user = unique_user_fn_scoped
    add_passkey(api_client, user, authenticator)

    started = registration_options(api_client, user)
    response = api_client.post(
        api_routes.users_self_passkeys,
        json={
            "challengeId": started["challengeId"],
            "name": "Again",
            "credential": authenticator.create(started["options"]),
        },
        headers=user.token,
    )
    assert response.status_code == 400


def test_only_mealie_password_users_can_add_passkeys(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, session: Session
):
    session.execute(update(User).where(User.id == unique_user_fn_scoped.user_id).values(auth_method=AuthMethod.OIDC))
    session.commit()

    response = api_client.post(
        api_routes.users_self_passkeys_registration_options,
        json={"currentPassword": unique_user_fn_scoped.password},
        headers=unique_user_fn_scoped.token,
    )
    assert response.status_code == 400


# ================================================================
# Signing in


def test_login_options_need_no_username(api_client: TestClient, passkeys_enabled):
    options = login_options(api_client)["options"]

    assert options["rpId"] == RP_ID
    assert options["allowCredentials"] == []
    assert options["userVerification"] == "required"


def test_sign_in_with_passkey(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    user = unique_user_fn_scoped
    created = add_passkey(api_client, user, authenticator)

    started = login_options(api_client)
    response = passkey_login(api_client, started["challengeId"], authenticator.get(started["options"]), True)
    assert response.status_code == 200, response.text

    body = response.json()
    assert body["token_type"] == "bearer"
    assert response.cookies.get("mealie.access_token") == body["access_token"]

    me = api_client.get(api_routes.users_self, headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["id"] == str(user.user_id)

    listed = api_client.get(api_routes.users_self_passkeys, headers=user.token).json()
    assert listed[0]["id"] == created["id"]
    assert listed[0]["lastUsedAt"] is not None


def test_sign_in_challenge_is_single_use(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    add_passkey(api_client, unique_user_fn_scoped, authenticator)

    started = login_options(api_client)
    credential = authenticator.get(started["options"])

    assert passkey_login(api_client, started["challengeId"], credential).status_code == 200
    assert passkey_login(api_client, started["challengeId"], credential).status_code == 401


def test_expired_sign_in_challenge_is_rejected(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    authenticator: SoftAuthenticator,
    session: Session,
):
    add_passkey(api_client, unique_user_fn_scoped, authenticator)
    started = login_options(api_client)

    session.execute(
        update(PasskeyChallenge)
        .where(PasskeyChallenge.id == started["challengeId"])
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    session.commit()

    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 401


def test_sign_in_with_unknown_passkey(api_client: TestClient, passkeys_enabled, authenticator: SoftAuthenticator):
    started = login_options(api_client)
    authenticator.user_handle = b"\x00" * 16

    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 401


def test_sign_in_with_mismatched_user_handle(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    unique_user: TestUser,
    authenticator: SoftAuthenticator,
):
    add_passkey(api_client, unique_user_fn_scoped, authenticator)
    started = login_options(api_client)

    credential = authenticator.get(started["options"], user_handle=unique_user.user_id.bytes)
    assert passkey_login(api_client, started["challengeId"], credential).status_code == 401


def test_sign_in_from_another_origin(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    add_passkey(api_client, unique_user_fn_scoped, authenticator)
    started = login_options(api_client)

    credential = authenticator.get(started["options"], origin="https://evil.example.com")
    assert passkey_login(api_client, started["challengeId"], credential).status_code == 401


def test_sign_in_needs_user_verification(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    """A passkey replaces the password, so holding the device isn't enough; the authenticator must check a PIN
    or biometric too."""
    add_passkey(api_client, unique_user_fn_scoped, authenticator)
    authenticator.user_verification = False

    started = login_options(api_client)
    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 401


def test_bad_signatures_lock_the_account(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    user = unique_user_fn_scoped
    add_passkey(api_client, user, authenticator)

    try:
        for _ in range(get_app_settings().SECURITY_MAX_LOGIN_ATTEMPTS):
            started = login_options(api_client)
            credential = authenticator.get(started["options"], tamper_signature=True)
            assert passkey_login(api_client, started["challengeId"], credential).status_code == 401

        # Locked out now, even with a good response
        started = login_options(api_client)
        response = passkey_login(api_client, started["challengeId"], authenticator.get(started["options"]))
        assert response.status_code == 423
    finally:
        # Other tests count locked users, so don't leave this one behind
        locked = user.repos.users.get_one(user.user_id)
        assert locked
        UserService(user.repos).unlock_user(locked)


def test_sign_count_must_increase(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    """A hardware key that keeps a counter and reports a lower one has probably been cloned."""
    authenticator.sign_count = 5
    add_passkey(api_client, unique_user_fn_scoped, authenticator)

    started = login_options(api_client)
    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 200

    authenticator.sign_count = 2
    started = login_options(api_client)
    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 401


def test_passkey_stops_working_when_user_leaves_mealie_auth(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    authenticator: SoftAuthenticator,
    session: Session,
):
    add_passkey(api_client, unique_user_fn_scoped, authenticator)
    session.execute(update(User).where(User.id == unique_user_fn_scoped.user_id).values(auth_method=AuthMethod.LDAP))
    session.commit()

    started = login_options(api_client)
    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 401


def test_deleted_passkey_no_longer_signs_in(
    api_client: TestClient, passkeys_enabled, unique_user_fn_scoped: TestUser, authenticator: SoftAuthenticator
):
    created = add_passkey(api_client, unique_user_fn_scoped, authenticator)
    api_client.delete(api_routes.users_self_passkeys_passkey_id(created["id"]), headers=unique_user_fn_scoped.token)

    started = login_options(api_client)
    assert passkey_login(api_client, started["challengeId"], authenticator.get(started["options"])).status_code == 401


def test_deleting_a_user_deletes_their_passkeys(
    api_client: TestClient,
    passkeys_enabled,
    unique_user_fn_scoped: TestUser,
    authenticator: SoftAuthenticator,
    admin_token,
    session: Session,
):
    add_passkey(api_client, unique_user_fn_scoped, authenticator)

    response = api_client.delete(api_routes.admin_users_item_id(unique_user_fn_scoped.user_id), headers=admin_token)
    assert response.status_code == 200

    session.expire_all()
    assert session.query(UserPasskey).filter_by(user_id=unique_user_fn_scoped.user_id).count() == 0

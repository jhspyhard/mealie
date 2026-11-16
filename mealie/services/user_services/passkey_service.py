import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import UUID4
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json_dict,
    parse_authentication_credential_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from mealie.repos.all_repositories import get_repositories
from mealie.repos.repository_factory import AllRepositories
from mealie.schema.user.passkeys import (
    PasskeyChallengeSave,
    PasskeyOptionsOut,
    UserPasskeyCreate,
    UserPasskeyInDB,
    UserPasskeyOut,
    UserPasskeySave,
)
from mealie.schema.user.user import PrivateUser
from mealie.services._base_service import BaseService

CHALLENGE_LIFETIME = timedelta(minutes=5)
"""How long the user has to finish with their authenticator. The browser is given the same timeout."""

KNOWN_TRANSPORTS = {transport.value for transport in AuthenticatorTransport}


class PasskeyPurpose(StrEnum):
    registration = "registration"
    authentication = "authentication"


class PasskeyError(Exception):
    """The browser's response couldn't be accepted. The message is for the logs, not the user."""


class PasskeyService(BaseService):
    """WebAuthn ceremonies for adding passkeys and signing in with them.

    Passkeys stand in for the password, so both ceremonies insist on user verification (a PIN, fingerprint or face
    check on the authenticator). Without it a passkey would be a single factor: whoever holds the device.
    """

    def __init__(self, repos: AllRepositories) -> None:
        self.repos = repos
        super().__init__()

    @property
    def _rp_id(self) -> str:
        return self.settings.PASSKEYS_RP_ID

    @property
    def _origin(self) -> str:
        return self.settings.PASSKEYS_ORIGIN

    # ================================================================
    # Challenges

    def _issue_challenge(self, purpose: PasskeyPurpose, user_id: UUID4 | None = None) -> tuple[UUID4, bytes]:
        self.repos.passkey_challenges.delete_expired()

        challenge = secrets.token_bytes(32)
        saved = self.repos.passkey_challenges.create(
            PasskeyChallengeSave(
                challenge=bytes_to_base64url(challenge),
                purpose=purpose.value,
                user_id=user_id,
                expires_at=datetime.now(UTC) + CHALLENGE_LIFETIME,
            )
        )
        return saved.id, challenge

    def take_challenge(self, challenge_id: UUID4, purpose: PasskeyPurpose, user_id: UUID4 | None = None) -> bytes:
        """Uses up a challenge, returning its bytes. It's gone afterwards whether or not the response checks out."""
        challenge = self.repos.passkey_challenges.consume(challenge_id, purpose.value)
        if challenge is None:
            raise PasskeyError("Challenge is unknown, expired or already used")
        if challenge.user_id != user_id:
            raise PasskeyError("Challenge was issued to a different user")

        return base64url_to_bytes(challenge.challenge)

    # ================================================================
    # Adding a passkey

    def registration_options(self, user: PrivateUser) -> PasskeyOptionsOut:
        existing = self.repos.user_passkeys.multi_query({"user_id": user.id})
        challenge_id, challenge = self._issue_challenge(PasskeyPurpose.registration, user.id)

        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=self.settings.branding.name,
            # The user handle is stored on the authenticator, so it must not be personal data. The id is random.
            user_id=user.id.bytes,
            user_name=user.email,
            user_display_name=user.full_name or user.email,
            challenge=challenge,
            timeout=int(CHALLENGE_LIFETIME.total_seconds() * 1000),
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                # Discoverable, so sign-in doesn't have to start with a username
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            # Stops the browser from registering an authenticator this user already has a passkey on
            exclude_credentials=[self._descriptor(passkey) for passkey in existing],
        )

        return PasskeyOptionsOut(challenge_id=challenge_id, options=options_to_json_dict(options))

    def register(self, user: PrivateUser, data: UserPasskeyCreate) -> UserPasskeyOut:
        challenge = self.take_challenge(data.challenge_id, PasskeyPurpose.registration, user.id)

        try:
            verified = verify_registration_response(
                credential=data.credential,
                expected_challenge=challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                require_user_verification=True,
            )
        except (WebAuthnException, ValueError, TypeError, KeyError) as e:
            raise PasskeyError(f"Registration response rejected: {e}") from e

        credential_id = bytes_to_base64url(verified.credential_id)
        unscoped = get_repositories(self.repos.session, group_id=None, household_id=None)
        if unscoped.user_passkeys.get_one(credential_id, "credential_id"):
            raise PasskeyError("This passkey is already registered")

        saved = self.repos.user_passkeys.create(
            UserPasskeySave(
                user_id=user.id,
                name=data.name,
                credential_id=credential_id,
                public_key=bytes_to_base64url(verified.credential_public_key),
                sign_count=verified.sign_count,
                transports=self._transports_from(data.credential),
                aaguid=verified.aaguid,
                backup_eligible=verified.credential_device_type == CredentialDeviceType.MULTI_DEVICE,
                backed_up=verified.credential_backed_up,
            )
        )
        return UserPasskeyOut.model_validate(saved)

    # ================================================================
    # Signing in

    def authentication_options(self) -> PasskeyOptionsOut:
        challenge_id, challenge = self._issue_challenge(PasskeyPurpose.authentication)

        options = generate_authentication_options(
            rp_id=self._rp_id,
            challenge=challenge,
            timeout=int(CHALLENGE_LIFETIME.total_seconds() * 1000),
            # Left empty so the browser offers whichever of the user's passkeys it has for this site; nothing
            # here reveals which accounts exist.
            allow_credentials=[],
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        return PasskeyOptionsOut(challenge_id=challenge_id, options=options_to_json_dict(options))

    def find_passkey(self, credential: dict[str, Any]) -> tuple[AuthenticationCredential, UserPasskeyInDB]:
        """Finds the stored passkey a sign-in response claims to come from, before its signature is checked."""
        try:
            parsed = parse_authentication_credential_json(credential)
        except (WebAuthnException, ValueError, TypeError, KeyError) as e:
            raise PasskeyError(f"Malformed authentication response: {e}") from e

        unscoped = get_repositories(self.repos.session, group_id=None, household_id=None)
        passkey = unscoped.user_passkeys.get_one(bytes_to_base64url(parsed.raw_id), "credential_id")
        if passkey is None:
            raise PasskeyError("Unknown passkey")

        # With no allowCredentials list the authenticator must say whose passkey it is, and it has to agree with
        # the owner on record (WebAuthn §7.2 step 6).
        if parsed.response.user_handle != passkey.user_id.bytes:
            raise PasskeyError("Passkey's user handle doesn't match its owner")

        return parsed, passkey

    def verify_authentication(
        self, credential: AuthenticationCredential, passkey: UserPasskeyInDB, challenge: bytes
    ) -> UserPasskeyInDB:
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                credential_public_key=base64url_to_bytes(passkey.public_key),
                credential_current_sign_count=passkey.sign_count,
                require_user_verification=True,
            )
        except (WebAuthnException, ValueError, TypeError, KeyError) as e:
            raise PasskeyError(f"Authentication response rejected: {e}") from e

        return self.repos.user_passkeys.patch(
            passkey.id,
            {
                "sign_count": verified.new_sign_count,
                "backed_up": verified.credential_backed_up,
                "last_used_at": datetime.now(UTC),
            },
        )

    # ================================================================
    # Helpers

    @staticmethod
    def _descriptor(passkey: UserPasskeyInDB) -> PublicKeyCredentialDescriptor:
        transports = [AuthenticatorTransport(t) for t in (passkey.transports or "").split(",") if t in KNOWN_TRANSPORTS]
        return PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(passkey.credential_id), transports=transports or None
        )

    @staticmethod
    def _transports_from(credential: dict[str, Any]) -> str | None:
        """The transports the browser reported, which come back as hints in exclude lists."""
        response = credential.get("response")
        reported = response.get("transports") if isinstance(response, dict) else None
        if not isinstance(reported, list):
            return None

        transports = [t for t in reported if isinstance(t, str) and t in KNOWN_TRANSPORTS]
        return ",".join(transports) or None

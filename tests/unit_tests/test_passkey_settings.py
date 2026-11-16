import pytest

from mealie.core.config import get_app_settings
from mealie.core.settings.settings import AppSettings


@pytest.fixture(autouse=True)
def reset_settings_cache():
    yield
    get_app_settings.cache_clear()


def settings_with(monkeypatch: pytest.MonkeyPatch, base_url: str, enabled: bool = True) -> AppSettings:
    monkeypatch.setenv("PASSKEYS_ENABLED", str(enabled).lower())
    monkeypatch.setenv("BASE_URL", base_url)
    get_app_settings.cache_clear()
    return get_app_settings()


def test_passkeys_off_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PASSKEYS_ENABLED", raising=False)
    get_app_settings.cache_clear()

    feature = get_app_settings().PASSKEYS_FEATURE
    assert feature.enabled is False
    assert feature.description == "PASSKEYS_ENABLED is false"


@pytest.mark.parametrize(
    "base_url",
    [
        "https://mealie.example.com",
        "https://mealie.example.com:8443/",
        "https://recipes.home.lan",
        "http://localhost:3000",
        "http://mealie.localhost:9000",
    ],
)
def test_secure_base_urls_allow_passkeys(monkeypatch: pytest.MonkeyPatch, base_url: str):
    feature = settings_with(monkeypatch, base_url).PASSKEYS_FEATURE
    assert feature.enabled is True
    assert feature.description is None


@pytest.mark.parametrize(
    ("base_url", "reason"),
    [
        ("http://localhost:8080", "BASE_URL must be set"),
        ("http://mealie.example.com", "must use https://"),
        ("https://192.168.5.234:9443", "domain name"),
        ("https://[fd00::1]", "domain name"),
        ("mealie.example.com", "full URL"),
    ],
)
def test_insecure_base_urls_disable_passkeys(monkeypatch: pytest.MonkeyPatch, base_url: str, reason: str):
    feature = settings_with(monkeypatch, base_url).PASSKEYS_FEATURE
    assert feature.enabled is False
    assert feature.description is not None
    assert reason in feature.description


@pytest.mark.parametrize(
    ("base_url", "rp_id", "origin"),
    [
        ("https://Mealie.Example.com/", "mealie.example.com", "https://mealie.example.com"),
        ("https://mealie.example.com:443", "mealie.example.com", "https://mealie.example.com"),
        ("https://mealie-test.l33ch.xh:9443", "mealie-test.l33ch.xh", "https://mealie-test.l33ch.xh:9443"),
        ("https://mealie.example.com/recipes", "mealie.example.com", "https://mealie.example.com"),
        ("http://localhost:3000", "localhost", "http://localhost:3000"),
    ],
)
def test_rp_id_and_origin_come_from_base_url(monkeypatch: pytest.MonkeyPatch, base_url: str, rp_id: str, origin: str):
    settings = settings_with(monkeypatch, base_url)
    assert settings.PASSKEYS_RP_ID == rp_id
    assert settings.PASSKEYS_ORIGIN == origin

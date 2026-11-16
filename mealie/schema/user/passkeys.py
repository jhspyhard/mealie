from datetime import datetime
from typing import Annotated, Any

from pydantic import UUID4, ConfigDict, StringConstraints

from mealie.schema._mealie import MealieModel
from mealie.schema._mealie.mealie_model import MealieOutModel

PasskeyName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class UserPasskeyOut(MealieOutModel):
    """A passkey as its owner sees it in their account settings."""

    id: UUID4
    name: str
    backed_up: bool = False
    """Synced across the user's devices by their password manager, rather than stored on one device."""
    created_at: datetime | None = None
    last_used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class UserPasskeyInDB(UserPasskeyOut):
    """Everything stored for a passkey. Only for the server's own use, never returned by the API."""

    user_id: UUID4
    credential_id: str
    public_key: str
    sign_count: int = 0
    transports: str | None = None
    aaguid: str | None = None
    backup_eligible: bool = False


class UserPasskeySave(MealieModel):
    user_id: UUID4
    name: str
    credential_id: str
    public_key: str
    sign_count: int = 0
    transports: str | None = None
    aaguid: str | None = None
    backup_eligible: bool = False
    backed_up: bool = False


class PasskeyChallengeSave(MealieModel):
    challenge: str
    purpose: str
    expires_at: datetime
    user_id: UUID4 | None = None


class PasskeyChallengeOut(PasskeyChallengeSave):
    id: UUID4

    model_config = ConfigDict(from_attributes=True)


class PasskeyRegistrationOptionsRequest(MealieModel):
    """Starts adding a passkey. The password is asked for again so a session left open on someone else's
    screen can't be used to add a passkey that outlives it."""

    current_password: str


class PasskeyOptionsOut(MealieOutModel):
    """What the browser needs to create or use a passkey."""

    challenge_id: UUID4
    """Send this back with the browser's response."""
    options: dict[str, Any]
    """WebAuthn `publicKey` options in their JSON form, for `PublicKeyCredential.parseCreationOptionsFromJSON()`
    or `parseRequestOptionsFromJSON()`."""


class UserPasskeyCreate(MealieModel):
    challenge_id: UUID4
    name: PasskeyName
    credential: dict[str, Any]
    """The browser's `PublicKeyCredential`, from `credential.toJSON()`."""


class PasskeyLoginRequest(MealieModel):
    challenge_id: UUID4
    credential: dict[str, Any]
    """The browser's `PublicKeyCredential`, from `credential.toJSON()`."""
    remember_me: bool = False

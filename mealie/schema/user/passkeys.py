from datetime import datetime
from typing import Annotated, Any

from pydantic import UUID4, ConfigDict, StringConstraints

from mealie.schema._mealie import MealieModel
from mealie.schema._mealie.mealie_model import MealieOutModel

PasskeyName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class UserPasskeyOut(MealieOutModel):
    """A passkey, as its owner sees it in the account settings."""

    id: UUID4
    name: str
    backed_up: bool = False
    """True when a password manager syncs the passkey across the devices of the user."""
    created_at: datetime | None = None
    last_used_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class UserPasskeyInDB(UserPasskeyOut):
    """All stored data for a passkey. Only the server uses this schema. The API does not return it."""

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
    """Starts a passkey registration. The user must give the password again. Thus a person who finds an open
    session on a different screen cannot add a passkey."""

    current_password: str


class PasskeyOptionsOut(MealieOutModel):
    """The data that the browser needs to create or use a passkey."""

    challenge_id: UUID4
    """Send this value back with the response from the browser."""
    options: dict[str, Any]
    """The WebAuthn `publicKey` options as JSON, for `PublicKeyCredential.parseCreationOptionsFromJSON()`
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

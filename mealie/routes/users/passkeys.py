from fastapi import HTTPException, status
from pydantic import UUID4

from mealie.core.security.providers.credentials_provider import CredentialsProvider
from mealie.db.models.users.users import AuthMethod
from mealie.routes._base import BaseUserController, controller
from mealie.routes._base.permissions import not_found
from mealie.routes._base.routers import UserAPIRouter
from mealie.schema.response import ErrorResponse
from mealie.schema.user.passkeys import (
    PasskeyOptionsOut,
    PasskeyRegistrationOptionsRequest,
    UserPasskeyCreate,
    UserPasskeyOut,
)
from mealie.services.user_services.passkey_service import PasskeyError, PasskeyService

router = UserAPIRouter(prefix="/users/self/passkeys", tags=["Users: Passkeys"])


@controller(router)
class UserPasskeysController(BaseUserController):
    """The passkeys of the signed-in user.

    Users can list and remove passkeys when passkeys are off, so they can remove passkeys that do not work.
    To add a passkey, passkeys must be on.
    """

    @property
    def service(self) -> PasskeyService:
        return PasskeyService(self.repos)

    def _assert_can_add_passkeys(self) -> None:
        if not self.settings.PASSKEYS_READY:
            raise not_found()

        if self.user.auth_method != AuthMethod.MEALIE:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, ErrorResponse.respond(self.t("user.passkeys-unavailable-for-auth-method"))
            )

    @router.get("", response_model=list[UserPasskeyOut])
    def get_passkeys(self):
        return [
            UserPasskeyOut.model_validate(passkey)
            for passkey in self.repos.user_passkeys.multi_query({"user_id": self.user.id}, order_by="created_at")
        ]

    @router.post("/registration-options", response_model=PasskeyOptionsOut)
    def get_registration_options(self, data: PasskeyRegistrationOptionsRequest):
        """Starts adding a passkey. Hand `options` to `navigator.credentials.create()`."""
        self._assert_can_add_passkeys()

        if not CredentialsProvider.verify_password(data.current_password, self.user.password):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, ErrorResponse.respond(self.t("user.invalid-current-password"))
            )

        return self.service.registration_options(self.user)

    @router.post("", response_model=UserPasskeyOut, status_code=status.HTTP_201_CREATED)
    def create_passkey(self, data: UserPasskeyCreate):
        """Finishes adding a passkey with the browser's response to the registration options."""
        self._assert_can_add_passkeys()

        try:
            return self.service.register(self.user, data)
        except PasskeyError as e:
            self.logger.warning(f"Passkey registration for user {self.user.id} rejected: {e}")
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, ErrorResponse.respond(self.t("user.passkey-registration-failed"))
            ) from e

    @router.delete("/{passkey_id}", response_model=UserPasskeyOut)
    def delete_passkey(self, passkey_id: UUID4):
        passkey = self.repos.user_passkeys.get_one(passkey_id)

        # The response for the passkey of a different user is the same as for a missing passkey.
        # Thus a user cannot find which passkey ids exist.
        if passkey is None or passkey.user_id != self.user.id:
            raise not_found()

        deleted = self.repos.user_passkeys.delete(passkey_id)
        return UserPasskeyOut.model_validate(deleted)

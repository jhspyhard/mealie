from datetime import timedelta

from sqlalchemy.orm.session import Session

from mealie.core import root_logger
from mealie.core.config import get_app_settings
from mealie.core.exceptions import UserLockedOut
from mealie.core.security.providers.auth_provider import AuthProvider
from mealie.db.models.users.users import AuthMethod
from mealie.repos.all_repositories import get_repositories
from mealie.schema.user.passkeys import PasskeyLoginRequest
from mealie.services.user_services.passkey_service import PasskeyError, PasskeyPurpose, PasskeyService
from mealie.services.user_services.user_service import UserService


class PasskeyProvider(AuthProvider[PasskeyLoginRequest]):
    """Signs a user in with a passkey in place of the password.

    The password lockout rules apply. A locked account stays locked. A response for a known passkey that fails
    verification counts as a failed attempt.
    """

    _logger = root_logger.get_logger("passkey_provider")

    def __init__(self, session: Session, data: PasskeyLoginRequest) -> None:
        super().__init__(session, data)

    def authenticate(self) -> tuple[str, timedelta] | None:
        settings = get_app_settings()
        db = get_repositories(self.session, group_id=None, household_id=None)
        service = PasskeyService(db)

        try:
            challenge = service.take_challenge(self.data.challenge_id, PasskeyPurpose.authentication)
            credential, passkey = service.find_passkey(self.data.credential)
        except PasskeyError as e:
            self._logger.warning(f"Passkey sign-in rejected: {e}")
            return None

        user = db.users.get_one(passkey.user_id)
        if user is None:
            return None

        # A passkey replaces a Mealie password, so it does not work for LDAP or OIDC accounts
        if user.auth_method != AuthMethod.MEALIE:
            self._logger.warning("Passkey belongs to a user whose auth method is not 'Mealie'; refusing sign-in")
            return None

        if user.login_attemps >= settings.SECURITY_MAX_LOGIN_ATTEMPTS or user.is_locked:
            raise UserLockedOut()

        try:
            service.verify_authentication(credential, passkey, challenge)
        except PasskeyError as e:
            self._logger.warning(f"Passkey sign-in rejected: {e}")
            user.login_attemps += 1
            db.users.update(user.id, user)

            if user.login_attemps >= settings.SECURITY_MAX_LOGIN_ATTEMPTS:
                UserService(db).lock_user(user)

            return None

        user.login_attemps = 0
        user = db.users.update(user.id, user)
        return self.get_access_token(user, self.data.remember_me)

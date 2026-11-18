from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, String, orm
from sqlalchemy.ext.associationproxy import AssociationProxy, association_proxy
from sqlalchemy.orm import Mapped, mapped_column

from .._model_base import BaseMixins, SqlAlchemyBase
from .._model_utils.datetime import NaiveDateTime
from .._model_utils.guid import GUID

if TYPE_CHECKING:
    from .users import User


class UserPasskey(SqlAlchemyBase, BaseMixins):
    """A WebAuthn credential that a user registered. The user signs in with it in place of the password."""

    __tablename__ = "user_passkeys"

    id: Mapped[GUID] = mapped_column(GUID, primary_key=True, default=GUID.generate)
    user_id: Mapped[GUID] = mapped_column(GUID, ForeignKey("users.id"), nullable=False, index=True)
    user: Mapped[User] = orm.relationship("User", back_populates="passkeys")

    group_id: AssociationProxy[GUID] = association_proxy("user", "group_id")
    household_id: AssociationProxy[GUID] = association_proxy("user", "household_id")

    name: Mapped[str] = mapped_column(String(64), nullable=False)

    credential_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    """The base64url credential ID. The authenticator sends it at each sign-in.
    The server uses it to find the passkey."""

    public_key: Mapped[str] = mapped_column(String, nullable=False)
    """The base64url COSE public key."""

    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    """The signature counter of the authenticator. Synced passkeys always send 0. Only hardware keys
    increase the counter, so a lower counter is a problem only for hardware keys."""

    transports: Mapped[str | None] = mapped_column(String, default=None)
    """The transports that the authenticator reported (internal, hybrid, usb, ...), separated by commas.
    The browser uses them as hints."""

    aaguid: Mapped[str | None] = mapped_column(String(36), default=None)
    """Identifies the authenticator model. It is all zeros when the authenticator does not give its model."""

    backup_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    backed_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """True when a password manager syncs the passkey (for example iCloud Keychain). False when one device keeps it."""

    last_used_at: Mapped[datetime | None] = mapped_column(NaiveDateTime, default=None)

    def __init__(
        self,
        user_id,
        name,
        credential_id,
        public_key,
        sign_count=0,
        transports=None,
        aaguid=None,
        backup_eligible=False,
        backed_up=False,
        last_used_at=None,
        **_,
    ) -> None:
        self.user_id = user_id
        self.name = name
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.transports = transports
        self.aaguid = aaguid
        self.backup_eligible = backup_eligible
        self.backed_up = backed_up
        self.last_used_at = last_used_at


class PasskeyChallenge(SqlAlchemyBase, BaseMixins):
    """A WebAuthn challenge for one response from the browser.

    The database keeps the challenge, so all workers can find it. The server deletes the challenge when it reads it.
    Thus an attacker cannot send a copied response again.
    """

    __tablename__ = "passkey_challenges"

    id: Mapped[GUID] = mapped_column(GUID, primary_key=True, default=GUID.generate)
    challenge: Mapped[str] = mapped_column(String, nullable=False)
    """Random bytes in base64url. The authenticator signs them."""

    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    """"registration" or "authentication". A challenge for one purpose is not valid for the other purpose."""

    user_id: Mapped[GUID | None] = mapped_column(GUID, default=None)
    """The user who adds a passkey. Empty for sign-in, because the server identifies the user from the response.
    This column is not a foreign key. The row expires after some minutes, so it must not prevent a user deletion."""

    expires_at: Mapped[datetime] = mapped_column(NaiveDateTime, nullable=False, index=True)

    def __init__(self, challenge, purpose, expires_at, user_id=None, **_) -> None:
        self.challenge = challenge
        self.purpose = purpose
        self.expires_at = expires_at
        self.user_id = user_id

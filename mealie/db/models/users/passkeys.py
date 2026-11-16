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
    """A WebAuthn credential a user registered to sign in with instead of their password."""

    __tablename__ = "user_passkeys"

    id: Mapped[GUID] = mapped_column(GUID, primary_key=True, default=GUID.generate)
    user_id: Mapped[GUID] = mapped_column(GUID, ForeignKey("users.id"), nullable=False, index=True)
    user: Mapped[User] = orm.relationship("User", back_populates="passkeys")

    group_id: AssociationProxy[GUID] = association_proxy("user", "group_id")
    household_id: AssociationProxy[GUID] = association_proxy("user", "household_id")

    name: Mapped[str] = mapped_column(String(64), nullable=False)
    """What the user called it, e.g. "Work laptop"."""

    credential_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    """base64url credential ID. The authenticator sends it back on every sign-in, which is how we find the key."""

    public_key: Mapped[str] = mapped_column(String, nullable=False)
    """base64url COSE public key. Not secret, but only the server needs it."""

    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    """The authenticator's signature counter. Synced passkeys always report 0, so a counter that goes backwards
    only means something for hardware keys that keep one."""

    transports: Mapped[str | None] = mapped_column(String, default=None)
    """Comma-separated transports the authenticator reported (internal, hybrid, usb, ...), as hints for the browser."""

    aaguid: Mapped[str | None] = mapped_column(String(36), default=None)
    """Identifies the authenticator model (or all zeros when it won't say)."""

    backup_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    backed_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """Whether the passkey is synced (e.g. iCloud Keychain, Google Password Manager) rather than device-bound."""

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
    """A WebAuthn challenge waiting for the browser's response.

    Kept in the database rather than in memory so it works with more than one worker, and deleted as it is used
    so a captured response can't be replayed.
    """

    __tablename__ = "passkey_challenges"

    id: Mapped[GUID] = mapped_column(GUID, primary_key=True, default=GUID.generate)
    challenge: Mapped[str] = mapped_column(String, nullable=False)
    """base64url random bytes the authenticator must sign."""

    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    """"registration" or "authentication", so one kind can't be redeemed as the other."""

    user_id: Mapped[GUID | None] = mapped_column(GUID, default=None)
    """The user adding a passkey; empty for sign-in, where we don't know who it is until the response arrives.
    Deliberately not a foreign key: the row expires within minutes and shouldn't block deleting a user."""

    expires_at: Mapped[datetime] = mapped_column(NaiveDateTime, nullable=False, index=True)

    def __init__(self, challenge, purpose, expires_at, user_id=None, **_) -> None:
        self.challenge = challenge
        self.purpose = purpose
        self.expires_at = expires_at
        self.user_id = user_id

from datetime import UTC, datetime

from pydantic import UUID4
from sqlalchemy import delete

from mealie.db.models.users.passkeys import PasskeyChallenge
from mealie.schema.user.passkeys import PasskeyChallengeOut

from .repository_generic import RepositoryGeneric


class RepositoryPasskeyChallenges(RepositoryGeneric[PasskeyChallengeOut, PasskeyChallenge]):
    def delete_expired(self) -> None:
        """Deletes expired challenges. A sign-in that a user stops before the end leaves its challenge in the table."""
        try:
            self.session.execute(delete(PasskeyChallenge).where(PasskeyChallenge.expires_at <= datetime.now(UTC)))
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def consume(self, challenge_id: UUID4, purpose: str) -> PasskeyChallengeOut | None:
        """Deletes the challenge and returns it.

        Returns None if the challenge is unknown, expired or for a different purpose.

        One DELETE ... RETURNING statement reads and deletes the challenge. Thus, when two requests send the same
        response at the same time, only one request gets the challenge.
        """
        stmt = (
            delete(PasskeyChallenge)
            .where(
                PasskeyChallenge.id == challenge_id,
                PasskeyChallenge.purpose == purpose,
                PasskeyChallenge.expires_at > datetime.now(UTC),
            )
            .returning(
                PasskeyChallenge.id,
                PasskeyChallenge.challenge,
                PasskeyChallenge.purpose,
                PasskeyChallenge.user_id,
                PasskeyChallenge.expires_at,
            )
        )
        try:
            row = self.session.execute(stmt).first()
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

        if row is None:
            return None

        return PasskeyChallengeOut(
            id=row.id, challenge=row.challenge, purpose=row.purpose, user_id=row.user_id, expires_at=row.expires_at
        )

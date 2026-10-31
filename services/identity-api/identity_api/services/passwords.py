import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from starlette.concurrency import run_in_threadpool

from identity_api.core.settings import Settings


@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    # Set when the password was right but the stored hash uses outdated parameters. The caller
    # saves it in the same transaction as the login.
    new_hash: str | None = None


class PasswordService:
    """Argon2id hashing. The CPU-heavy calls run in a thread pool so they do not block the loop."""

    def __init__(self, settings: Settings) -> None:
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
        )
        # Verified against when the email is unknown, so that path costs the same as a real one.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    async def hash(self, password: str) -> str:
        return await run_in_threadpool(self._hasher.hash, password)

    async def verify_login(self, stored_hash: str | None, password: str) -> PasswordCheck:
        """Checks a login attempt; `stored_hash` is None when no admin has that email.

        An unknown email still pays for a full verification, and the result is the same
        `ok=False` as for a wrong password.
        """
        target = stored_hash or self._dummy_hash
        matches = await run_in_threadpool(self._verify, target, password)
        if stored_hash is None or not matches:
            return PasswordCheck(ok=False)
        new_hash = None
        if self._hasher.check_needs_rehash(stored_hash):
            new_hash = await self.hash(password)
        return PasswordCheck(ok=True, new_hash=new_hash)

    def _verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            # Wrong password or a hash we cannot parse: both are a failed login.
            return False

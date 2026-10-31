import hashlib
import logging
import math
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis

from identity_api.core.settings import Settings

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]


class InvalidRefreshTokenError(Exception):
    """The refresh token is unknown, expired, revoked or was already used."""


@dataclass(frozen=True)
class RefreshSession:
    token: str
    family_id: str
    expires_at: datetime


@dataclass(frozen=True)
class Rotation:
    admin_id: uuid.UUID
    session: RefreshSession


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class RefreshTokenStore:
    """Refresh-token families in Redis (ADR 0009). Only SHA-256 hashes of tokens are stored.

    Keys:
      `rf:<family>`   hash {admin_id, expires_at}; the family and its hard limit (30 days)
      `ra:<admin>`    set of the admin's family IDs, so a password change can end them all
      `rt:<hash>`     the family a token belongs to; lives as long as the token
      `rtu:<hash>`    marker set when the token is used (SET NX makes "first use" atomic)
    """

    def __init__(
        self, redis: Redis, settings: Settings, clock: Clock = lambda: datetime.now(UTC)
    ) -> None:
        self._redis = redis
        self._token_ttl = timedelta(days=settings.refresh_token_ttl_days)
        self._family_ttl = timedelta(days=settings.refresh_family_max_days)
        self._clock = clock

    async def start_family(self, admin_id: uuid.UUID) -> RefreshSession:
        """Starts a new family at login (or after a password change)."""
        now = self._clock()
        family_id = secrets.token_urlsafe(16)
        family_expires = now + self._family_ttl
        family_seconds = _seconds(self._family_ttl)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(
                f"rf:{family_id}",
                mapping={"admin_id": str(admin_id), "expires_at": family_expires.timestamp()},
            )
            pipe.expire(f"rf:{family_id}", family_seconds)
            pipe.sadd(f"ra:{admin_id}", family_id)
            pipe.expire(f"ra:{admin_id}", family_seconds)
            await pipe.execute()
        return await self._issue(family_id, family_expires, now)

    async def rotate(self, token: str) -> Rotation:
        """Exchanges a refresh token for the next one in its family.

        A token that was already used revokes the whole family (it was probably stolen) and
        raises like any other invalid token.
        """
        token_hash = hash_token(token)
        family_id = await self._redis.hget(f"rt:{token_hash}", "family_id")
        if family_id is None:
            raise InvalidRefreshTokenError("unknown or expired token")
        family_id = _text(family_id)
        family = await self._redis.hgetall(f"rf:{family_id}")
        if not family:
            raise InvalidRefreshTokenError("family revoked or expired")
        fields = {_text(key): _text(value) for key, value in family.items()}
        now = self._clock()
        family_expires = datetime.fromtimestamp(float(fields["expires_at"]), UTC)
        if family_expires <= now:
            await self.revoke_family(family_id)
            raise InvalidRefreshTokenError("family expired")

        first_use = await self._redis.set(
            f"rtu:{token_hash}", "1", nx=True, ex=_seconds(self._token_ttl)
        )
        if not first_use:
            logger.warning("refresh token reuse detected", extra={"family_id": family_id})
            await self.revoke_family(family_id)
            raise InvalidRefreshTokenError("token reuse")

        session = await self._issue(family_id, family_expires, now)
        return Rotation(uuid.UUID(fields["admin_id"]), session)

    async def family_id_of(self, token: str) -> str | None:
        """The family a token belongs to, or None if it is unknown or expired (for rate limits)."""
        family_id = await self._redis.hget(f"rt:{hash_token(token)}", "family_id")
        return None if family_id is None else _text(family_id)

    async def revoke_family(self, family_id: str) -> None:
        admin_id = await self._redis.hget(f"rf:{family_id}", "admin_id")
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(f"rf:{family_id}")
            if admin_id is not None:
                pipe.srem(f"ra:{_text(admin_id)}", family_id)
            await pipe.execute()

    async def revoke_by_token(self, token: str) -> None:
        """Logout: ends the family the token belongs to. An unknown token is ignored."""
        family_id = await self._redis.hget(f"rt:{hash_token(token)}", "family_id")
        if family_id is not None:
            await self.revoke_family(_text(family_id))

    async def revoke_all(self, admin_id: uuid.UUID) -> None:
        family_ids = await self._redis.smembers(f"ra:{admin_id}")
        for family_id in family_ids:
            await self.revoke_family(_text(family_id))
        await self._redis.delete(f"ra:{admin_id}")

    async def _issue(
        self, family_id: str, family_expires: datetime, now: datetime
    ) -> RefreshSession:
        """Creates the next token, which never outlives its family."""
        expires_at = min(now + self._token_ttl, family_expires)
        token = secrets.token_urlsafe(32)  # 256 bits
        ttl = max(1, math.ceil((expires_at - now).total_seconds()))
        await self._redis.hset(f"rt:{hash_token(token)}", "family_id", family_id)
        await self._redis.expire(f"rt:{hash_token(token)}", ttl)
        return RefreshSession(token, family_id, expires_at)


def _seconds(delta: timedelta) -> int:
    return int(delta.total_seconds())


def _text(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value

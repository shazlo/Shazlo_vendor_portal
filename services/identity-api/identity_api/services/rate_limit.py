import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from identity_api.core.errors import ApiError
from identity_api.core.settings import RateRule, Settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    count: int
    retry_after: int  # seconds until the window resets, at least 1


class RateLimiter(Protocol):
    """Counts hits per key. The store behind it can change without touching the endpoints."""

    async def hit(self, key: str, rule: RateRule) -> RateLimitResult:
        """Counts one hit. Allowed while the count in the current window is within the limit."""
        ...

    async def reset(self, key: str) -> None: ...


class RedisRateLimiter:
    """Fixed window: the first hit starts the window and the key expires with it.

    A client can use up the limit at the end of one window and again at the start of the next,
    so a burst of up to twice the limit can pass across a boundary. That is fine for brute-force
    protection, and the TTL gives an exact `Retry-After`.
    """

    def __init__(self, redis: Redis, prefix: str = "rl:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def hit(self, key: str, rule: RateRule) -> RateLimitResult:
        name = self._prefix + key
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incr(name)
            pipe.ttl(name)
            count, ttl = await pipe.execute()
        if ttl < 0:
            # The first hit, or a key whose expiry was lost: either way, (re)start the window.
            await self._redis.expire(name, rule.window_seconds)
            ttl = rule.window_seconds
        return RateLimitResult(count <= rule.limit, count, max(1, ttl))

    async def reset(self, key: str) -> None:
        await self._redis.delete(self._prefix + key)


@dataclass(frozen=True)
class Check:
    """One counter an endpoint is limited by, e.g. `Check("ip", "203.0.113.7", rule)`."""

    scope: str
    subject: str
    rule: RateRule


class RateLimitGuard:
    """Applies the checks of an endpoint, answers 429 and decides what a Redis outage means."""

    def __init__(self, limiter: RateLimiter, settings: Settings) -> None:
        self._limiter = limiter
        self._fail_closed = set(settings.rate_limit_fail_closed)
        key = settings.rate_limit_hmac_key
        if key is None:  # Settings fills it in, so this is a programming error
            raise ValueError("rate_limit_hmac_key is not set")
        self._hmac_key = key.get_secret_value().encode()

    def _key(self, endpoint: str, scope: str, subject: str) -> str:
        # Subjects are hashed, so Redis never holds an email (or IP) in plain text. A keyed hash
        # because emails are guessable: a plain hash could be reversed from a Redis dump.
        digest = hmac.new(self._hmac_key, subject.encode(), hashlib.sha256).hexdigest()
        return f"{endpoint}:{scope}:{digest}"

    async def check(self, endpoint: str, checks: list[Check]) -> None:
        """Counts a hit on every check; raises 429 if any is over its limit.

        Every counter is hit even when an earlier one is over, so the counters stay honest.
        """
        try:
            results = [
                await self._limiter.hit(self._key(endpoint, c.scope, c.subject), c.rule)
                for c in checks
            ]
        except RedisError as error:
            self._store_down(endpoint, error)
            return
        denied = [result for result in results if not result.allowed]
        if denied:
            retry_after = max(result.retry_after for result in denied)
            raise ApiError(
                429,
                "rate_limited",
                "Too many requests. Try again later.",
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )

    async def reset(self, endpoint: str, scope: str, subject: str) -> None:
        """Clears one counter (a successful login clears the email's). Never fails the request."""
        try:
            await self._limiter.reset(self._key(endpoint, scope, subject))
        except RedisError:
            logger.warning("rate limit reset failed", extra={"endpoint": endpoint})

    def _store_down(self, endpoint: str, error: RedisError) -> None:
        if endpoint in self._fail_closed:
            logger.error(
                "rate limiter unavailable, refusing", exc_info=error, extra={"endpoint": endpoint}
            )
            raise ApiError(
                503, "rate_limiter_unavailable", "Service temporarily unavailable"
            ) from error
        logger.warning(
            "rate limiter unavailable, allowing", exc_info=error, extra={"endpoint": endpoint}
        )

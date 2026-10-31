import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)

# ADR 0009: services cache the key set for 10 minutes and refetch at most once per minute.
CACHE_TTL_SECONDS = 600.0
MIN_REFETCH_INTERVAL_SECONDS = 60.0
MIN_KEY_BITS = 2048
MAX_RESPONSE_BYTES = 256 * 1024

Fetcher = Callable[[], Awaitable[dict[str, Any]]]
Clock = Callable[[], float]


class JwksError(Exception):
    """The key set could not be fetched or holds no usable key."""


def http_fetcher(url: str, *, timeout: float = 3.0) -> Fetcher:
    """Fetches the JWKS document over HTTP. A short timeout: a slow identity-api must not
    hold requests (the lock below makes other requests wait for the fetch)."""

    async def fetch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise JwksError("JWKS response is too large")
        document = response.json()
        if not isinstance(document, dict):
            raise JwksError("JWKS response is not a JSON object")
        return document

    return fetch


def parse_jwks(document: dict[str, Any]) -> dict[str, rsa.RSAPublicKey]:
    """The usable RSA signing keys by `kid`. Anything else in the document is skipped.

    Raises JwksError if nothing usable is left, so a broken response never replaces good keys.
    """
    raw = document.get("keys")
    if not isinstance(raw, list):
        raise JwksError("JWKS has no 'keys' list")
    keys: dict[str, rsa.RSAPublicKey] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        usable = (
            isinstance(kid, str)
            and kid
            and entry.get("kty") == "RSA"
            and entry.get("use", "sig") == "sig"
            and entry.get("alg", "RS256") == "RS256"
        )
        if not usable:
            continue
        try:
            key = RSAAlgorithm.from_jwk(entry)
        except Exception:  # noqa: BLE001 - one bad key must not hide the good ones
            logger.warning("skipping unreadable JWKS key", extra={"kid": kid})
            continue
        if isinstance(key, rsa.RSAPublicKey) and key.key_size >= MIN_KEY_BITS:
            keys[str(kid)] = key
    if not keys:
        raise JwksError("JWKS holds no usable RS256 key")
    return keys


class JwksClient:
    """Public keys from a JWKS endpoint, fetched rarely (ADR 0009).

    - The keys are cached for `cache_ttl` seconds. Verifying a token never fetches by itself
      unless the cache has run out or the token names a `kid` that is not cached.
    - No fetch starts less than `min_refetch_interval` seconds after the previous attempt, so
      neither a flood of unknown `kid`s nor an outage can turn into a request per token.
    - Concurrent callers share one fetch.
    - If a fetch fails, the last good keys stay in use (stale, but better than no sign-in) and
      the next attempt waits for the interval. Before the first success, tokens are rejected.
    """

    def __init__(
        self,
        fetch: Fetcher,
        *,
        cache_ttl: float = CACHE_TTL_SECONDS,
        min_refetch_interval: float = MIN_REFETCH_INTERVAL_SECONDS,
        clock: Clock = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._cache_ttl = cache_ttl
        self._min_interval = min_refetch_interval
        self._clock = clock
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._fetched_at: float | None = None  # last success
        self._attempted_at: float | None = None  # last attempt, success or not
        self._lock = asyncio.Lock()

    @classmethod
    def from_url(cls, url: str, **options: Any) -> "JwksClient":
        return cls(http_fetcher(url), **options)

    async def get_key(self, kid: str) -> rsa.RSAPublicKey | None:
        if self._is_fresh() and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            # Another caller may have refreshed while this one waited for the lock.
            if self._is_fresh() and kid in self._keys:
                return self._keys[kid]
            if self._may_fetch():
                await self._refresh()
        return self._keys.get(kid)

    def _is_fresh(self) -> bool:
        return self._fetched_at is not None and self._clock() - self._fetched_at < self._cache_ttl

    def _may_fetch(self) -> bool:
        return (
            self._attempted_at is None or self._clock() - self._attempted_at >= self._min_interval
        )

    async def _refresh(self) -> None:
        self._attempted_at = self._clock()
        try:
            keys = parse_jwks(await self._fetch())
        except Exception as error:  # noqa: BLE001 - any failure keeps the last good keys
            logger.warning(
                "JWKS fetch failed, keeping the cached keys",
                exc_info=error,
                extra={"cached_keys": len(self._keys)},
            )
            return
        self._keys = keys
        self._fetched_at = self._clock()

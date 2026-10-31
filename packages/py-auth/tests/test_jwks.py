import asyncio
import math
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shazlo_auth import JwksClient, JwksError
from shazlo_auth.jwks import parse_jwks
from tests.helpers import jwk_of

Keys = dict[str, rsa.RSAPrivateKey]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeJwks:
    """A JWKS endpoint that counts fetches and can be changed or broken."""

    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document
        self.fetches = 0
        self.failing = False
        self.delay = 0.0

    async def __call__(self) -> dict[str, Any]:
        self.fetches += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.failing:
            raise ConnectionError("identity-api is down")
        return self.document


def document(private_keys: Keys, *kids: str) -> dict[str, Any]:
    return {"keys": [jwk_of(kid, private_keys[kid]) for kid in kids]}


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def endpoint(private_keys: Keys) -> FakeJwks:
    return FakeJwks(document(private_keys, "key-1"))


@pytest.fixture
def client(endpoint: FakeJwks, clock: Clock) -> JwksClient:
    return JwksClient(endpoint, clock=clock)


# --- Caching ---------------------------------------------------------------------------


async def test_keys_are_fetched_once_and_then_cached(
    client: JwksClient, endpoint: FakeJwks
) -> None:
    for _ in range(100):
        assert await client.get_key("key-1") is not None
    assert endpoint.fetches == 1


async def test_the_cache_lasts_10_minutes(
    client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    await client.get_key("key-1")
    clock.advance(599)
    await client.get_key("key-1")
    assert endpoint.fetches == 1
    clock.advance(2)  # 601 seconds since the fetch
    await client.get_key("key-1")
    assert endpoint.fetches == 2


async def test_concurrent_requests_share_one_fetch(endpoint: FakeJwks, clock: Clock) -> None:
    endpoint.delay = 0.05
    client = JwksClient(endpoint, clock=clock)
    keys = await asyncio.gather(*(client.get_key("key-1") for _ in range(50)))
    assert all(key is not None for key in keys)
    assert endpoint.fetches == 1


# --- Unknown kid -----------------------------------------------------------------------


async def test_an_unknown_kid_refetches_at_most_once_a_minute(
    client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    await client.get_key("key-1")  # fetch 1, at t=0
    clock.advance(10)
    for _ in range(50):  # a flood of tokens with a kid nobody has
        assert await client.get_key("nobody") is None
    assert endpoint.fetches == 1  # still inside the minute since the last attempt

    clock.advance(50)  # t=60
    for _ in range(50):
        assert await client.get_key("nobody") is None
    assert endpoint.fetches == 2  # one refetch, not fifty

    clock.advance(59)
    await client.get_key("nobody")
    assert endpoint.fetches == 2
    clock.advance(1)
    await client.get_key("nobody")
    assert endpoint.fetches == 3


async def test_fetches_over_ten_minutes_are_bounded(
    client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    """Whatever the traffic, one fetch per minute at most (and one per TTL when all is well)."""
    for second in range(600):
        clock.advance(1)
        await client.get_key("key-1" if second % 2 else "nobody")
    assert endpoint.fetches <= math.ceil(600 / 60) + 1


async def test_failed_fetches_are_also_bounded(
    client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    endpoint.failing = True
    for _ in range(600):
        clock.advance(1)
        await client.get_key("key-1")
    assert endpoint.fetches <= 10


# --- Rotation --------------------------------------------------------------------------


async def test_a_new_key_is_picked_up_on_its_first_token(
    private_keys: Keys, client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    assert await client.get_key("key-1") is not None
    endpoint.document = document(private_keys, "key-1", "key-2")  # key-2 is published
    clock.advance(61)
    assert await client.get_key("key-2") is not None  # an unknown kid triggered the refetch
    assert await client.get_key("key-1") is not None  # the old key stays while it is listed
    assert endpoint.fetches == 2


async def test_a_new_key_is_unknown_for_up_to_a_minute_after_the_last_fetch(
    private_keys: Keys, client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    """The price of the bound: a token signed with a brand new key within 60 seconds of the
    last fetch is rejected. ADR 0009 avoids this by publishing a key one cache TTL before use."""
    await client.get_key("key-1")
    endpoint.document = document(private_keys, "key-1", "key-2")
    clock.advance(5)
    assert await client.get_key("key-2") is None
    clock.advance(56)
    assert await client.get_key("key-2") is not None


async def test_a_retired_key_is_dropped_after_the_cache_expires(
    private_keys: Keys, client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    endpoint.document = document(private_keys, "key-1", "key-2")
    assert await client.get_key("key-1") is not None
    endpoint.document = document(private_keys, "key-2")  # key-1 removed from the JWKS
    clock.advance(601)
    assert await client.get_key("key-2") is not None
    assert await client.get_key("key-1") is None


# --- Outages ---------------------------------------------------------------------------


async def test_the_last_good_keys_survive_an_outage_past_the_ttl(
    client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    assert await client.get_key("key-1") is not None
    endpoint.failing = True
    clock.advance(601)
    assert await client.get_key("key-1") is not None  # stale, but kept
    assert endpoint.fetches == 2  # the failed attempt
    clock.advance(3600)
    assert await client.get_key("key-1") is not None
    assert await client.get_key("nobody") is None


async def test_the_client_recovers_when_the_endpoint_is_back(
    private_keys: Keys, client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    await client.get_key("key-1")
    endpoint.failing = True
    clock.advance(601)
    await client.get_key("key-1")
    endpoint.failing = False
    endpoint.document = document(private_keys, "key-2")
    clock.advance(30)
    assert await client.get_key("key-2") is None  # inside the minute after the failed attempt
    clock.advance(31)
    assert await client.get_key("key-2") is not None


async def test_before_the_first_success_nothing_is_trusted_and_retries_are_bounded(
    client: JwksClient, endpoint: FakeJwks, clock: Clock
) -> None:
    endpoint.failing = True
    for _ in range(30):
        assert await client.get_key("key-1") is None
    assert endpoint.fetches == 1
    endpoint.failing = False
    assert await client.get_key("key-1") is None  # still inside the minute
    clock.advance(60)
    assert await client.get_key("key-1") is not None


@pytest.mark.parametrize(
    "bad",
    [{}, {"keys": []}, {"keys": "nope"}, {"keys": [{"kty": "oct", "kid": "x", "k": "AA"}]}],
)
async def test_a_bad_document_does_not_replace_good_keys(
    client: JwksClient, endpoint: FakeJwks, clock: Clock, bad: dict[str, Any]
) -> None:
    await client.get_key("key-1")
    endpoint.document = bad
    clock.advance(601)
    assert await client.get_key("key-1") is not None


# --- Parsing ---------------------------------------------------------------------------


def test_parse_keeps_only_usable_rsa_signing_keys(private_keys: Keys) -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    parsed = parse_jwks(
        {
            "keys": [
                jwk_of("good", private_keys["key-1"]),
                jwk_of("encryption", private_keys["key-2"], use="enc"),
                jwk_of("other-alg", private_keys["key-2"], alg="RS512"),
                jwk_of("no-alg", private_keys["key-3"], alg=None) | {"alg": None},
                jwk_of("small", small),
                {**jwk_of("", private_keys["key-2"])},
                {k: v for k, v in jwk_of("nokid", private_keys["key-2"]).items() if k != "kid"},
                {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
                {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"},
                "not a dict",
            ]
        }
    )
    assert set(parsed) == {"good"}


def test_parse_accepts_keys_without_use_or_alg(private_keys: Keys) -> None:
    jwk = {
        k: v for k, v in jwk_of("plain", private_keys["key-1"]).items() if k not in ("use", "alg")
    }
    assert set(parse_jwks({"keys": [jwk]})) == {"plain"}


def test_parse_raises_when_nothing_is_usable() -> None:
    with pytest.raises(JwksError):
        parse_jwks({"keys": []})

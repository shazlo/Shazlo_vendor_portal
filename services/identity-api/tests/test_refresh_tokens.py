import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import FakeAsyncRedis

from identity_api.core.settings import Settings
from identity_api.services.refresh_tokens import (
    InvalidRefreshTokenError,
    RefreshTokenStore,
    hash_token,
)

ADMIN = uuid.UUID("11111111-2222-3333-4444-555555555555")
START = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    client = FakeAsyncRedis()
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(redis: FakeAsyncRedis, settings: Settings, clock: Clock) -> RefreshTokenStore:
    return RefreshTokenStore(redis, settings, clock=clock)


async def test_token_is_256_bits_and_only_its_hash_is_stored(
    store: RefreshTokenStore, redis: FakeAsyncRedis
) -> None:
    session = await store.start_family(ADMIN)
    assert len(session.token) >= 43  # 32 random bytes, base64url
    keys = [_text(key) async for key in redis.scan_iter("*")]
    assert f"rt:{hash_token(session.token)}" in keys
    assert not any(session.token in key for key in keys)
    for key in keys:
        # Whatever the key's type, the raw token must not appear in its value.
        for value in await _dump_values(redis, key):
            assert session.token not in value


def _text(value: bytes | str) -> str:
    return value.decode() if isinstance(value, bytes) else value


async def _dump_values(redis: FakeAsyncRedis, key: str) -> list[str]:
    kind = _text(await redis.type(key))
    if kind == "hash":
        return [_text(v) for v in (await redis.hgetall(key)).values()]
    if kind == "set":
        return [_text(v) for v in await redis.smembers(key)]
    value = await redis.get(key)
    return [_text(value)] if value else []


async def test_rotation_gives_a_new_token_in_the_same_family(store: RefreshTokenStore) -> None:
    first = await store.start_family(ADMIN)
    rotation = await store.rotate(first.token)
    assert rotation.admin_id == ADMIN
    assert rotation.session.token != first.token
    assert rotation.session.family_id == first.family_id
    # The new token rotates in turn.
    assert (await store.rotate(rotation.session.token)).admin_id == ADMIN


async def test_reusing_a_rotated_token_revokes_the_family(store: RefreshTokenStore) -> None:
    first = await store.start_family(ADMIN)
    second = (await store.rotate(first.token)).session
    with pytest.raises(InvalidRefreshTokenError):
        await store.rotate(first.token)
    # The token handed out after the first one is dead too.
    with pytest.raises(InvalidRefreshTokenError):
        await store.rotate(second.token)


async def test_unknown_token_is_rejected(store: RefreshTokenStore) -> None:
    with pytest.raises(InvalidRefreshTokenError):
        await store.rotate("never-issued")


async def test_token_lifetime_is_seven_days(store: RefreshTokenStore, clock: Clock) -> None:
    session = await store.start_family(ADMIN)
    assert session.expires_at == START + timedelta(days=7)


async def test_family_ends_thirty_days_after_login(store: RefreshTokenStore, clock: Clock) -> None:
    session = await store.start_family(ADMIN)
    # Keep refreshing every 6 days: each token is valid, but the family has a hard limit.
    for _ in range(4):
        clock.now += timedelta(days=6)
        session = (await store.rotate(session.token)).session
    clock.now = START + timedelta(days=28)
    # The last token may not outlive the family.
    last = (await store.rotate(session.token)).session
    assert last.expires_at == START + timedelta(days=30)
    clock.now = START + timedelta(days=30, seconds=1)
    with pytest.raises(InvalidRefreshTokenError):
        await store.rotate(last.token)


async def test_revoke_by_token_ends_the_family(store: RefreshTokenStore) -> None:
    session = await store.start_family(ADMIN)
    await store.revoke_by_token(session.token)
    with pytest.raises(InvalidRefreshTokenError):
        await store.rotate(session.token)
    await store.revoke_by_token("unknown")  # ignored


async def test_revoke_all_ends_every_family_of_the_admin_only(
    store: RefreshTokenStore,
) -> None:
    mine = [await store.start_family(ADMIN) for _ in range(3)]
    other = await store.start_family(uuid.uuid4())
    await store.revoke_all(ADMIN)
    for session in mine:
        with pytest.raises(InvalidRefreshTokenError):
            await store.rotate(session.token)
    assert (await store.rotate(other.token)).session.family_id == other.family_id


async def test_keys_expire_in_redis(store: RefreshTokenStore, redis: FakeAsyncRedis) -> None:
    session = await store.start_family(ADMIN)
    assert 0 < await redis.ttl(f"rt:{hash_token(session.token)}") <= 7 * 86400
    assert 0 < await redis.ttl(f"rf:{session.family_id}") <= 30 * 86400

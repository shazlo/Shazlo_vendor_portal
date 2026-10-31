import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from typing import Any

import httpx
import pytest
from fakeredis import FakeAsyncRedis, FakeServer
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from identity_api.app import create_app
from identity_api.core.client_ip import client_ip, parse_networks
from identity_api.core.errors import ApiError
from identity_api.core.settings import RateRule, Settings
from identity_api.db.models import Admin, Role
from identity_api.db.session import get_session
from identity_api.services.passwords import PasswordService
from identity_api.services.rate_limit import (
    Check,
    RateLimitGuard,
    RedisRateLimiter,
)

PASSWORD = "correct horse battery"
EMAIL = "reviewer@shazlo.test"


def rule(limit: int, window: int = 60) -> RateRule:
    return RateRule(limit=limit, window_seconds=window)


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    client = FakeAsyncRedis()
    yield client
    await client.flushall()
    await client.aclose()


# --- Limiter -----------------------------------------------------------------------------


async def test_hits_are_allowed_up_to_the_limit(redis: FakeAsyncRedis) -> None:
    limiter = RedisRateLimiter(redis)
    results = [await limiter.hit("k", rule(3)) for _ in range(5)]
    assert [r.allowed for r in results] == [True, True, True, False, False]
    assert [r.count for r in results] == [1, 2, 3, 4, 5]


async def test_retry_after_is_the_time_left_in_the_window(redis: FakeAsyncRedis) -> None:
    limiter = RedisRateLimiter(redis)
    first = await limiter.hit("k", rule(1, window=60))
    assert first.retry_after == 60
    blocked = await limiter.hit("k", rule(1, window=60))
    assert not blocked.allowed
    assert 59 <= blocked.retry_after <= 60
    # The window does not slide: blocked hits do not push the reset further away.
    assert await redis.ttl("rl:k") <= 60


async def test_the_window_resets(redis: FakeAsyncRedis) -> None:
    limiter = RedisRateLimiter(redis)
    assert (await limiter.hit("k", rule(1, window=1))).allowed
    assert not (await limiter.hit("k", rule(1, window=1))).allowed
    await asyncio.sleep(1.2)
    again = await limiter.hit("k", rule(1, window=1))
    assert again.allowed
    assert again.count == 1


async def test_keys_are_counted_separately(redis: FakeAsyncRedis) -> None:
    limiter = RedisRateLimiter(redis)
    assert (await limiter.hit("a", rule(1))).allowed
    assert not (await limiter.hit("a", rule(1))).allowed
    assert (await limiter.hit("b", rule(1))).allowed


async def test_reset_clears_the_counter(redis: FakeAsyncRedis) -> None:
    limiter = RedisRateLimiter(redis)
    await limiter.hit("k", rule(1))
    await limiter.reset("k")
    assert (await limiter.hit("k", rule(1))).allowed


async def test_a_counter_that_lost_its_expiry_gets_one_again(redis: FakeAsyncRedis) -> None:
    await redis.set("rl:k", 7)  # e.g. a crash between INCR and EXPIRE
    result = await RedisRateLimiter(redis).hit("k", rule(5, window=30))
    assert not result.allowed
    assert 0 < await redis.ttl("rl:k") <= 30


# --- Guard -------------------------------------------------------------------------------


def make_guard(
    settings: Settings, redis: FakeAsyncRedis, override: Callable[..., Settings], **changes: Any
) -> RateLimitGuard:
    return RateLimitGuard(RedisRateLimiter(redis), override(settings, **changes))


async def test_guard_answers_429_with_retry_after(
    settings: Settings, redis: FakeAsyncRedis, override: Callable[..., Settings]
) -> None:
    guard = make_guard(settings, redis, override)
    checks = [Check("ip", "203.0.113.7", rule(2, window=120))]
    await guard.check("login", checks)
    await guard.check("login", checks)
    with pytest.raises(ApiError) as caught:
        await guard.check("login", checks)
    error = caught.value
    assert (error.status_code, error.code) == (429, "rate_limited")
    assert error.headers is not None
    assert 119 <= int(error.headers["Retry-After"]) <= 120


async def test_retry_after_is_the_longest_of_the_checks_that_are_over(
    settings: Settings, redis: FakeAsyncRedis, override: Callable[..., Settings]
) -> None:
    guard = make_guard(settings, redis, override)
    checks = [Check("ip", "1.1.1.1", rule(1, window=10)), Check("email", "a@b.c", rule(1, 500))]
    await guard.check("login", checks)
    with pytest.raises(ApiError) as caught:
        await guard.check("login", checks)
    assert caught.value.headers is not None
    assert int(caught.value.headers["Retry-After"]) > 400


async def test_redis_holds_no_plain_subject(
    settings: Settings, redis: FakeAsyncRedis, override: Callable[..., Settings]
) -> None:
    guard = make_guard(settings, redis, override)
    await guard.check(
        "login",
        [
            Check("email", "Secret.Person@shazlo.test", rule(5)),
            Check("ip", "198.51.100.9", rule(5)),
        ],
    )
    keys = [key.decode() async for key in redis.scan_iter("*")]
    assert len(keys) == 2
    for key in keys:
        assert "secret" not in key.lower()
        assert "shazlo" not in key
        assert "198.51" not in key


async def test_the_hash_is_keyed(
    settings: Settings, redis: FakeAsyncRedis, override: Callable[..., Settings]
) -> None:
    """A plain SHA-256 of an email could be looked up; the key makes that useless."""
    one = make_guard(settings, redis, override, rate_limit_hmac_key="a" * 32)
    other = make_guard(settings, redis, override, rate_limit_hmac_key="b" * 32)
    await one.check("login", [Check("email", EMAIL, rule(5))])
    await other.check("login", [Check("email", EMAIL, rule(5))])
    assert len([key async for key in redis.scan_iter("*")]) == 2


async def test_two_instances_with_the_same_key_share_the_counter(
    settings: Settings, redis: FakeAsyncRedis, override: Callable[..., Settings]
) -> None:
    one = make_guard(settings, redis, override)
    other = make_guard(settings, redis, override)
    checks = [Check("email", EMAIL, rule(2))]
    await one.check("login", checks)
    await other.check("login", checks)
    with pytest.raises(ApiError):
        await one.check("login", checks)


@pytest.mark.parametrize(("endpoint", "closed"), [("login", True), ("token", False)])
async def test_redis_down_fails_closed_or_open_per_endpoint(
    settings: Settings,
    override: Callable[..., Settings],
    caplog: pytest.LogCaptureFixture,
    endpoint: str,
    closed: bool,
) -> None:
    server = FakeServer()
    server.connected = False
    client = FakeAsyncRedis(server=server)
    guard = make_guard(settings, client, override, rate_limit_fail_closed=["login"])
    with caplog.at_level(logging.WARNING):
        if closed:
            with pytest.raises(ApiError) as caught:
                await guard.check(endpoint, [Check("ip", "1.1.1.1", rule(1))])
            assert (caught.value.status_code, caught.value.code) == (
                503,
                "rate_limiter_unavailable",
            )
        else:
            await guard.check(endpoint, [Check("ip", "1.1.1.1", rule(1))])
    assert any("rate limiter unavailable" in record.getMessage() for record in caplog.records)
    await client.aclose()


async def test_a_failed_reset_never_fails_the_request(
    settings: Settings, override: Callable[..., Settings]
) -> None:
    server = FakeServer()
    server.connected = False
    client = FakeAsyncRedis(server=server)
    guard = make_guard(settings, client, override)
    await guard.reset("login", "email", EMAIL)  # does not raise
    await client.aclose()


# --- Client IP ---------------------------------------------------------------------------


def request_from(peer: str | None, *forwarded: str) -> Request:
    headers = [(b"x-forwarded-for", value.encode()) for value in forwarded]
    scope = {
        "type": "http",
        "headers": headers,
        "client": (peer, 1234) if peer else None,
        "method": "GET",
        "path": "/",
    }
    return Request(scope)


PROXIES = parse_networks(["10.0.0.0/8", "192.168.0.1/32"])


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        # Not from a trusted proxy: the header is ignored, however convincing it looks.
        ("203.0.113.5", ["198.51.100.1"], "203.0.113.5"),
        ("203.0.113.5", [], "203.0.113.5"),
        # From a trusted proxy: the last address that is not a proxy.
        ("10.0.0.1", ["198.51.100.1"], "198.51.100.1"),
        ("10.0.0.1", ["198.51.100.1, 10.0.0.7"], "198.51.100.1"),
        ("10.0.0.1", ["198.51.100.1", "10.0.0.7"], "198.51.100.1"),
        # What the client wrote further left cannot override what the proxy appended.
        ("10.0.0.1", ["6.6.6.6, 198.51.100.1"], "198.51.100.1"),
        ("10.0.0.1", ["1.1.1.1, 2.2.2.2, 10.0.0.9"], "2.2.2.2"),
        # No usable header: the proxy itself.
        ("10.0.0.1", [], "10.0.0.1"),
        ("10.0.0.1", ["garbage"], "10.0.0.1"),
        ("10.0.0.1", ["6.6.6.6, garbage"], "10.0.0.1"),
        ("192.168.0.1", ["2001:db8::1"], "2001:db8::1"),
        (None, ["1.1.1.1"], "unknown"),
        ("not-an-ip", ["1.1.1.1"], "unknown"),
    ],
)
def test_client_ip(peer: str | None, forwarded: list[str], expected: str) -> None:
    assert client_ip(request_from(peer, *forwarded), PROXIES) == expected


def test_no_trusted_proxies_means_the_header_is_never_read() -> None:
    assert client_ip(request_from("10.0.0.1", "198.51.100.1"), []) == "10.0.0.1"


# --- Endpoints ---------------------------------------------------------------------------

TRUST_LOCAL = ["127.0.0.0/8"]


@pytest.fixture
def api_settings(settings: Settings, override: Callable[..., Settings]) -> Settings:
    return override(
        settings,
        jwt_issuer="https://identity.test",
        argon2_memory_cost_kib=8,
        argon2_time_cost=1,
        # The test client connects from 127.0.0.1, so a trusted proxy there lets tests choose
        # the client IP with X-Forwarded-For.
        trusted_proxies=TRUST_LOCAL,
        rate_limit_login_ip="1000/60",
        rate_limit_login_email="3/60",
        rate_limit_refresh_ip="1000/60",
        rate_limit_refresh_session="1000/60",
        rate_limit_token_ip="1000/60",
        rate_limit_token_admin="1000/60",
        rate_limit_change_password_admin="1000/60",
        rate_limit_hmac_key="k" * 32,
    )


@asynccontextmanager
async def serve(
    settings: Settings, session: AsyncSession, redis: FakeAsyncRedis
) -> AsyncIterator[httpx.AsyncClient]:
    """One app instance. Several of them can share a Redis, like replicas would."""
    app = create_app(settings, readiness_checks={}, redis=redis)

    async def test_session() -> AsyncIterator[AsyncSession]:
        yield session

    app.dependency_overrides[get_session] = test_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://identity.test"
    ) as http:
        yield http


@pytest.fixture
async def client(
    api_settings: Settings, session: AsyncSession, redis: FakeAsyncRedis
) -> AsyncIterator[httpx.AsyncClient]:
    async with serve(api_settings, session, redis) as http:
        yield http


@pytest.fixture
async def admin(session: AsyncSession, api_settings: Settings) -> Admin:
    reviewer = Admin(
        email=EMAIL,
        password_hash=await PasswordService(api_settings).hash(PASSWORD),
        display_name="Reviewer",
        must_change_password=False,
        roles=[await session.get_one(Role, "vendor_reviewer")],
    )
    session.add(reviewer)
    await session.commit()
    return reviewer


async def sign_in(
    client: httpx.AsyncClient,
    email: str = EMAIL,
    password: str = PASSWORD,
    ip: str = "198.51.100.1",
) -> httpx.Response:
    client.cookies.clear()
    return await client.post(
        "/v1/auth/login",
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": ip},
    )


def retry_after(response: httpx.Response) -> int:
    return int(response.headers["retry-after"])


def refresh_cookie(response: httpx.Response) -> str | None:
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(header)
        if "refresh_token" in cookie:
            return cookie["refresh_token"].value
    return None


async def test_n_failed_logins_for_one_email_are_429_from_any_ip(
    client: httpx.AsyncClient, admin: Admin
) -> None:
    for number in range(3):
        failed = await sign_in(client, password="wrong password!!", ip=f"198.51.100.{number}")
        assert failed.status_code == 401
    # Different IP again, and even the right password: the email is locked for the window.
    blocked = await sign_in(client, ip="203.0.113.77")
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert 1 <= retry_after(blocked) <= 60
    assert retry_after(blocked) >= 55  # just started, so nearly the whole window
    assert blocked.headers["cache-control"] == "no-store"
    assert refresh_cookie(blocked) is None


async def test_unknown_emails_are_limited_the_same_way(client: httpx.AsyncClient) -> None:
    statuses = [(await sign_in(client, "nobody@shazlo.test", "x")).status_code for _ in range(5)]
    assert statuses == [401, 401, 401, 429, 429]


async def test_a_successful_login_clears_the_email_counter(
    client: httpx.AsyncClient, admin: Admin
) -> None:
    for _ in range(2):
        assert (await sign_in(client, password="wrong password!!")).status_code == 401
    assert (await sign_in(client)).status_code == 200
    for _ in range(2):
        assert (await sign_in(client, password="wrong password!!")).status_code == 401
    assert (await sign_in(client)).status_code == 200


async def test_emails_have_separate_counters(client: httpx.AsyncClient, admin: Admin) -> None:
    for _ in range(3):
        await sign_in(client, password="wrong password!!")
    assert (await sign_in(client)).status_code == 429
    assert (await sign_in(client, "someone.else@shazlo.test", "x")).status_code == 401


async def test_the_email_counter_ignores_letter_case_and_spaces(
    client: httpx.AsyncClient, admin: Admin
) -> None:
    for variant in (EMAIL, EMAIL.upper(), f" {EMAIL} "):
        assert (await sign_in(client, variant, "wrong password!!")).status_code == 401
    assert (await sign_in(client, EMAIL.title())).status_code == 429


async def test_login_is_limited_per_ip(
    client: httpx.AsyncClient,
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    override: Callable[..., Settings],
) -> None:
    strict = override(api_settings, rate_limit_login_ip="2/60")
    async with serve(strict, session, redis) as limited:
        # Different emails, so only the IP counter can stop this.
        results = [
            (await sign_in(limited, f"user{n}@shazlo.test", "x", ip="203.0.113.50")).status_code
            for n in range(4)
        ]
        assert results == [401, 401, 429, 429]
        # Another IP is unaffected.
        other = await sign_in(limited, "user9@shazlo.test", "x", ip="203.0.113.51")
        assert other.status_code == 401


async def test_a_forged_forwarded_header_does_not_dodge_the_ip_limit(
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    override: Callable[..., Settings],
) -> None:
    untrusting = override(api_settings, trusted_proxies=[], rate_limit_login_ip="2/60")
    async with serve(untrusting, session, redis) as http:
        results = [
            (await sign_in(http, f"user{n}@shazlo.test", "x", ip=f"203.0.113.{n}")).status_code
            for n in range(4)
        ]
    assert results == [401, 401, 429, 429]


async def test_limits_hold_across_two_instances_sharing_redis(
    api_settings: Settings, session: AsyncSession, redis: FakeAsyncRedis, admin: Admin
) -> None:
    async with (
        serve(api_settings, session, redis) as one,
        serve(api_settings, session, redis) as two,
    ):
        assert (await sign_in(one, password="wrong password!!")).status_code == 401
        assert (await sign_in(two, password="wrong password!!")).status_code == 401
        assert (await sign_in(one, password="wrong password!!")).status_code == 401
        # The fourth attempt reaches the other instance, which has seen only one of the three.
        assert (await sign_in(two)).status_code == 429
        assert (await sign_in(one)).status_code == 429


async def test_redis_holds_no_email_or_ip_after_logins(
    client: httpx.AsyncClient, admin: Admin, redis: FakeAsyncRedis
) -> None:
    await sign_in(client, password="wrong password!!", ip="198.51.100.23")
    keys = [key.decode() async for key in redis.scan_iter("rl:*")]
    assert len(keys) == 2
    assert all(
        "reviewer" not in key and "shazlo" not in key and "198.51" not in key for key in keys
    )


async def test_login_fails_closed_when_redis_is_down(
    api_settings: Settings, session: AsyncSession, admin: Admin
) -> None:
    server = FakeServer()
    redis = FakeAsyncRedis(server=server)
    async with serve(api_settings, session, redis) as http:
        server.connected = False
        response = await sign_in(http)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "rate_limiter_unavailable"
    assert refresh_cookie(response) is None


async def test_token_exchange_fails_open_when_redis_is_down(
    api_settings: Settings, session: AsyncSession, admin: Admin
) -> None:
    server = FakeServer()
    redis = FakeAsyncRedis(server=server)
    async with serve(api_settings, session, redis) as http:
        headers = {"Authorization": f"Bearer {(await sign_in(http)).json()['access_token']}"}
        server.connected = False
        response = await http.post(
            "/v1/auth/token", headers=headers, json={"audience": "vendor-api"}
        )
    assert response.status_code == 200


async def test_change_password_fails_closed_when_redis_is_down(
    api_settings: Settings, session: AsyncSession, admin: Admin
) -> None:
    server = FakeServer()
    redis = FakeAsyncRedis(server=server)
    async with serve(api_settings, session, redis) as http:
        headers = {"Authorization": f"Bearer {(await sign_in(http)).json()['access_token']}"}
        server.connected = False
        response = await http.post(
            "/v1/auth/change-password",
            headers=headers,
            json={"current_password": PASSWORD, "new_password": "another long passphrase"},
        )
    assert response.status_code == 503


async def test_token_exchange_is_limited_per_admin_and_per_ip(
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    admin: Admin,
    override: Callable[..., Settings],
) -> None:
    strict = override(api_settings, rate_limit_token_admin="2/60", rate_limit_token_ip="3/60")
    async with serve(strict, session, redis) as http:
        headers = {"Authorization": f"Bearer {(await sign_in(http)).json()['access_token']}"}

        async def exchange(ip: str) -> httpx.Response:
            return await http.post(
                "/v1/auth/token",
                headers={**headers, "X-Forwarded-For": ip},
                json={"audience": "vendor-api"},
            )

        assert (await exchange("203.0.113.1")).status_code == 200
        assert (await exchange("203.0.113.2")).status_code == 200
        blocked = await exchange("203.0.113.3")  # a new IP, but the admin is over the limit
        assert blocked.status_code == 429
        assert 1 <= retry_after(blocked) <= 60


async def test_token_exchange_ip_limit(
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    admin: Admin,
    override: Callable[..., Settings],
) -> None:
    strict = override(api_settings, rate_limit_token_ip="1/60")
    async with serve(strict, session, redis) as http:
        headers = {"Authorization": f"Bearer {(await sign_in(http)).json()['access_token']}"}
        body = {"audience": "vendor-api"}
        assert (await http.post("/v1/auth/token", headers=headers, json=body)).status_code == 200
        assert (await http.post("/v1/auth/token", headers=headers, json=body)).status_code == 429


async def test_refresh_is_limited_per_session_and_keeps_the_cookie(
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    admin: Admin,
    override: Callable[..., Settings],
) -> None:
    strict = override(api_settings, rate_limit_refresh_session="2/60")
    async with serve(strict, session, redis) as http:
        token = refresh_cookie(await sign_in(http))
        assert token is not None
        for _ in range(2):
            http.cookies.clear()
            response = await http.post(
                "/v1/auth/refresh", headers={"Cookie": f"refresh_token={token}"}
            )
            assert response.status_code == 200
            token = refresh_cookie(response)  # rotated: a new token, the same family
            assert token is not None
        http.cookies.clear()
        blocked = await http.post("/v1/auth/refresh", headers={"Cookie": f"refresh_token={token}"})
        assert blocked.status_code == 429
        assert blocked.json()["error"]["code"] == "rate_limited"
        assert 1 <= retry_after(blocked) <= 60
        # The limit says nothing about the token, so the cookie is not cleared.
        assert "refresh_token" not in blocked.headers.get("set-cookie", "")


async def test_refresh_is_limited_per_ip_even_without_a_cookie(
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    override: Callable[..., Settings],
) -> None:
    strict = override(api_settings, rate_limit_refresh_ip="2/60")
    async with serve(strict, session, redis) as http:
        statuses = [(await http.post("/v1/auth/refresh")).status_code for _ in range(4)]
    assert statuses == [401, 401, 429, 429]


async def test_change_password_is_limited_per_admin(
    api_settings: Settings,
    session: AsyncSession,
    redis: FakeAsyncRedis,
    admin: Admin,
    override: Callable[..., Settings],
) -> None:
    strict = override(api_settings, rate_limit_change_password_admin="2/60")
    async with serve(strict, session, redis) as http:
        headers = {"Authorization": f"Bearer {(await sign_in(http)).json()['access_token']}"}
        body = {"current_password": "not the password", "new_password": "another long passphrase"}
        statuses = [
            (await http.post("/v1/auth/change-password", headers=headers, json=body)).status_code
            for _ in range(3)
        ]
        assert statuses == [400, 400, 429]
        # Even the right current password is refused until the window is over.
        body["current_password"] = PASSWORD
        blocked = await http.post("/v1/auth/change-password", headers=headers, json=body)
        assert blocked.status_code == 429
        assert 1 <= retry_after(blocked) <= 60


async def test_other_endpoints_are_not_limited(client: httpx.AsyncClient, admin: Admin) -> None:
    headers = {"Authorization": f"Bearer {(await sign_in(client)).json()['access_token']}"}
    for _ in range(10):
        assert (await client.get("/v1/me", headers=headers)).status_code == 200

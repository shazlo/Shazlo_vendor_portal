"""The whole auth flow with real Postgres and Redis, and the token checked the way another
service checks it: through the JWKS, with `packages/py-auth`.

Skipped unless DATABASE_URL and REDIS_URL are set (CI sets both). The Redis database named in
REDIS_URL is emptied after each test, so give the tests their own (not database 0).
"""

import json
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from typing import Any

import httpx
import jwt
import pytest
from redis.asyncio import Redis
from shazlo_auth import InvalidTokenError, JwksClient, TokenVerifier
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.app import create_app
from identity_api.cli import seed_admin
from identity_api.core.settings import Settings
from identity_api.db.session import get_session
from identity_api.services.passwords import PasswordService

ISSUER = "https://identity.test"
SEED_EMAIL = "first.admin@shazlo.test"
SEED_PASSWORD = "a temporary seed password"
NEW_PASSWORD = "my own long passphrase"

TEST_REDIS_URL = os.environ.get("REDIS_URL", "")


@pytest.fixture
async def redis() -> AsyncIterator[Redis]:
    if not TEST_REDIS_URL:
        pytest.skip("REDIS_URL is not set")
    database = make_url(TEST_REDIS_URL).database
    if not database or database == "0":
        pytest.fail("REDIS_URL must name a database other than 0 (e.g. redis://localhost:6379/1)")
    client = Redis.from_url(TEST_REDIS_URL)
    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


@pytest.fixture
def e2e_settings(settings: Settings, override: Callable[..., Settings]) -> Settings:
    return override(settings, jwt_issuer=ISSUER)


@asynccontextmanager
async def serve(
    settings: Settings, session: AsyncSession, redis: Redis
) -> AsyncIterator[httpx.AsyncClient]:
    """One identity-api instance on the shared database and Redis."""
    app = create_app(settings, readiness_checks={}, redis=redis)

    async def test_session() -> AsyncIterator[AsyncSession]:
        yield session  # rolled back after the test

    app.dependency_overrides[get_session] = test_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://identity.test"
    ) as http:
        yield http


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def cookie_value(response: httpx.Response) -> str | None:
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(header)
        if "refresh_token" in cookie:
            return cookie["refresh_token"].value or None
    return None


def claims_of(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False})


def live_jwks(http: httpx.AsyncClient) -> JwksClient:
    """A JWKS client that reads the running app's `/.well-known/jwks.json`, as a service would."""

    async def fetch() -> dict[str, Any]:
        response = await http.get("/.well-known/jwks.json")
        response.raise_for_status()
        document: dict[str, Any] = response.json()
        return document

    return JwksClient(fetch)


async def test_the_whole_auth_flow(
    e2e_settings: Settings, session: AsyncSession, redis: Redis
) -> None:
    async with serve(e2e_settings, session, redis) as http:
        # 1. The seed script makes the first super_admin, who must change the password.
        created = await seed_admin(
            session,
            PasswordService(e2e_settings),
            email=SEED_EMAIL.upper(),
            password=SEED_PASSWORD,
            min_password_length=e2e_settings.password_min_length,
        )
        assert created

        # 2. First login: a token that grants nothing, and no way into the API yet.
        login = await http.post(
            "/v1/auth/login", json={"email": SEED_EMAIL, "password": SEED_PASSWORD}
        )
        assert login.status_code == 200
        assert login.json()["must_change_password"] is True
        pending = login.json()["access_token"]
        assert claims_of(pending)["roles"] == []
        assert cookie_value(login)
        blocked = await http.get("/v1/me", headers=bearer(pending))
        assert (blocked.status_code, blocked.json()["error"]["code"]) == (
            403,
            "password_change_required",
        )

        # 3. The forced password change ends the first session and starts a normal one.
        changed = await http.post(
            "/v1/auth/change-password",
            headers=bearer(pending),
            json={"current_password": SEED_PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert changed.status_code == 200
        assert changed.json()["must_change_password"] is False
        access = changed.json()["access_token"]
        first_refresh = cookie_value(changed)
        assert first_refresh

        # 4. GET /v1/me.
        me = await http.get("/v1/me", headers=bearer(access))
        assert me.status_code == 200
        admin = me.json()
        assert admin["email"] == SEED_EMAIL
        assert admin["roles"] == ["super_admin"]
        assert "password_hash" not in admin

        # 5. A token for vendor-api.
        exchange = await http.post(
            "/v1/auth/token", headers=bearer(access), json={"audience": "vendor-api"}
        )
        assert exchange.status_code == 200
        vendor_token = exchange.json()["access_token"]
        assert "refresh_token" not in exchange.headers.get("set-cookie", "")

        # 6. vendor-api would check it with packages/py-auth, through the live JWKS.
        jwks = await http.get("/.well-known/jwks.json")
        assert jwks.headers["cache-control"] == "max-age=600"
        verifier = TokenVerifier(live_jwks(http), issuer=ISSUER, audience="vendor-api")
        claims = await verifier.verify(vendor_token)
        assert str(claims.subject) == admin["id"]
        assert claims.roles == ("super_admin",)
        assert claims.must_change_password is False
        # The identity-api session token is for identity-api only.
        with pytest.raises(InvalidTokenError):
            await verifier.verify(access)

        # 7. Refresh rotates the token and gives a working access token.
        refreshed = await http.post("/v1/auth/refresh")  # the cookie jar sends the cookie
        assert refreshed.status_code == 200
        second_refresh = cookie_value(refreshed)
        assert second_refresh and second_refresh != first_refresh
        assert (
            await http.get("/v1/me", headers=bearer(refreshed.json()["access_token"]))
        ).status_code == 200

        # 8. Reuse detection: the first token again ends the whole family, even the new token.
        http.cookies.clear()
        replay = await http.post(
            "/v1/auth/refresh", headers={"Cookie": f"refresh_token={first_refresh}"}
        )
        assert (replay.status_code, replay.json()["error"]["code"]) == (
            401,
            "invalid_refresh_token",
        )
        dead = await http.post(
            "/v1/auth/refresh", headers={"Cookie": f"refresh_token={second_refresh}"}
        )
        assert dead.status_code == 401

        # 9. Logout ends a session.
        http.cookies.clear()
        again = await http.post(
            "/v1/auth/login", json={"email": SEED_EMAIL, "password": NEW_PASSWORD}
        )
        assert again.status_code == 200
        assert again.json()["must_change_password"] is False
        token = cookie_value(again)
        assert token
        assert (await http.post("/v1/auth/logout")).status_code == 204
        http.cookies.clear()
        gone = await http.post("/v1/auth/refresh", headers={"Cookie": f"refresh_token={token}"})
        assert gone.status_code == 401

        # Redis kept hashes only: no refresh token, email or password in any key.
        keys = [key.decode() async for key in redis.scan_iter("*")]
        assert keys
        for key in keys:
            assert token not in key
            assert first_refresh not in key
            assert "shazlo.test" not in key


async def test_key_rotation_with_a_token_in_flight(
    e2e_settings: Settings,
    session: AsyncSession,
    redis: Redis,
    key_pems: dict[str, str],
    override: Callable[..., Settings],
) -> None:
    """Follows the runbook: publish the new key, sign with it, retire the old one."""

    def keyed(signing: str, *kids: str) -> Settings:
        return override(
            e2e_settings,
            jwt_keys=json.dumps({kid: key_pems[kid] for kid in kids}),
            jwt_signing_kid=signing,
        )

    await seed_admin(
        session,
        PasswordService(e2e_settings),
        email=SEED_EMAIL,
        password=SEED_PASSWORD,
        min_password_length=e2e_settings.password_min_length,
    )
    # Past the forced change, so these are ordinary logins.
    async with serve(keyed("test-key-1", "test-key-1"), session, redis) as before:
        first = await before.post(
            "/v1/auth/login", json={"email": SEED_EMAIL, "password": SEED_PASSWORD}
        )
        token = first.json()["access_token"]
        changed = await before.post(
            "/v1/auth/change-password",
            headers=bearer(token),
            json={"current_password": SEED_PASSWORD, "new_password": NEW_PASSWORD},
        )
        in_flight = changed.json()["access_token"]  # signed with the old key
        session_cookie = cookie_value(changed)
    assert jwt.get_unverified_header(in_flight)["kid"] == "test-key-1"

    now = [1000.0]
    current: dict[str, httpx.AsyncClient] = {}

    async def fetch() -> dict[str, Any]:
        response = await current["http"].get("/.well-known/jwks.json")
        document: dict[str, Any] = response.json()
        return document

    verifier = TokenVerifier(
        JwksClient(fetch, clock=lambda: now[0]), issuer=ISSUER, audience="identity-api"
    )

    # Before: only the old key exists and the in-flight token verifies.
    async with serve(keyed("test-key-1", "test-key-1"), session, redis) as http:
        current["http"] = http
        assert (await verifier.verify(in_flight)).roles == ("super_admin",)

    # Step 2: the new key is published, the old one still signs.
    async with serve(keyed("test-key-1", "test-key-1", "test-key-2"), session, redis) as http:
        current["http"] = http
        jwks = (await http.get("/.well-known/jwks.json")).json()
        assert {key["kid"] for key in jwks["keys"]} == {"test-key-1", "test-key-2"}
        login = await http.post(
            "/v1/auth/login", json={"email": SEED_EMAIL, "password": NEW_PASSWORD}
        )
        assert jwt.get_unverified_header(login.json()["access_token"])["kid"] == "test-key-1"

    # Step 5: signing switches to the new key; both keys are published.
    async with serve(keyed("test-key-2", "test-key-1", "test-key-2"), session, redis) as http:
        current["http"] = http
        login = await http.post(
            "/v1/auth/login", json={"email": SEED_EMAIL, "password": NEW_PASSWORD}
        )
        new_token = login.json()["access_token"]
        assert jwt.get_unverified_header(new_token)["kid"] == "test-key-2"

        # The service has a cached key set without the new key: an unknown kid, so it refetches
        # (at most once a minute) and then accepts the new token. The in-flight one still works.
        now[0] += 61
        assert (await verifier.verify(new_token)).roles == ("super_admin",)
        assert (await verifier.verify(in_flight)).roles == ("super_admin",)

        # The session survives the rotation: refresh gives a token signed with the new key.
        http.cookies.clear()
        refreshed = await http.post(
            "/v1/auth/refresh", headers={"Cookie": f"refresh_token={session_cookie}"}
        )
        assert refreshed.status_code == 200
        assert jwt.get_unverified_header(refreshed.json()["access_token"])["kid"] == "test-key-2"

    # Step 7: the old key is retired. Once the service's cache refreshes, tokens it signed
    # are refused and tokens from the new key are fine.
    async with serve(keyed("test-key-2", "test-key-2"), session, redis) as http:
        current["http"] = http
        now[0] += 601
        assert (await verifier.verify(new_token)).roles == ("super_admin",)
        with pytest.raises(InvalidTokenError, match="unknown kid"):
            await verifier.verify(in_flight)

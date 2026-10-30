import json
import logging
from collections.abc import AsyncIterator, Callable
from http.cookies import Morsel, SimpleCookie
from typing import Annotated, Any

import httpx
import jwt
import pytest
from fakeredis import FakeAsyncRedis
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.api.deps import current_admin
from identity_api.app import create_app
from identity_api.core.settings import Settings
from identity_api.db.models import Admin, Role
from identity_api.db.session import get_session
from identity_api.services.passwords import PasswordService
from identity_api.services.refresh_tokens import hash_token

ORIGIN = "https://shell.test"
PASSWORD = "correct horse battery"
NEW_PASSWORD = "another long passphrase"

MakeAdmin = Callable[..., Any]


@pytest.fixture
def api_settings(settings: Settings, override: Callable[..., Settings]) -> Settings:
    return override(
        settings,
        jwt_issuer="https://identity.test",
        cors_allowed_origins=[ORIGIN],
        # Small costs keep the password tests fast.
        argon2_memory_cost_kib=8,
        argon2_time_cost=1,
    )


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    client = FakeAsyncRedis()
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
async def client(
    api_settings: Settings, session: AsyncSession, redis: FakeAsyncRedis
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(api_settings, readiness_checks={}, redis=redis)

    async def test_session() -> AsyncIterator[AsyncSession]:
        yield session  # rolled back after the test, so tests share no rows

    app.dependency_overrides[get_session] = test_session

    @app.get("/v1/protected")
    async def protected(admin: Annotated[Admin, Depends(current_admin)]) -> dict[str, str]:
        return {"email": admin.email}

    transport = httpx.ASGITransport(app=app)
    # https, so the client treats the Secure refresh cookie as sendable.
    async with httpx.AsyncClient(transport=transport, base_url="https://identity.test") as http:
        http.app = app  # type: ignore[attr-defined]
        yield http


@pytest.fixture
def make_admin(api_settings: Settings, session: AsyncSession) -> MakeAdmin:
    passwords = PasswordService(api_settings)

    async def make(
        email: str = "reviewer@shazlo.test",
        *,
        password: str = PASSWORD,
        role: str = "vendor_reviewer",
        is_active: bool = True,
        must_change_password: bool = False,
    ) -> Admin:
        admin = Admin(
            email=email,
            password_hash=await passwords.hash(password),
            display_name="Test Admin",
            is_active=is_active,
            must_change_password=must_change_password,
            roles=[await session.get_one(Role, role)],
        )
        session.add(admin)
        await session.commit()
        return admin

    return make


def refresh_cookie(response: httpx.Response) -> Morsel[str] | None:
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(header)
        if "refresh_token" in cookie:
            return cookie["refresh_token"]
    return None


def refresh_token(response: httpx.Response) -> str:
    morsel = refresh_cookie(response)
    assert morsel is not None and morsel.value
    return morsel.value


async def login(client: httpx.AsyncClient, email: str = "reviewer@shazlo.test") -> httpx.Response:
    client.cookies.clear()
    return await client.post("/v1/auth/login", json={"email": email, "password": PASSWORD})


async def refresh_with(client: httpx.AsyncClient, token: str) -> httpx.Response:
    client.cookies.clear()
    return await client.post("/v1/auth/refresh", headers={"Cookie": f"refresh_token={token}"})


def bearer(response: httpx.Response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# --- login ---------------------------------------------------------------------------------


async def test_login_returns_token_profile_and_cookie(
    client: httpx.AsyncClient, make_admin: MakeAdmin, session: AsyncSession
) -> None:
    admin = await make_admin()
    response = await login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert body["must_change_password"] is False
    assert body["admin"] == {
        "id": str(admin.id),
        "email": "reviewer@shazlo.test",
        "display_name": "Test Admin",
        "roles": ["vendor_reviewer"],
        "must_change_password": False,
    }
    assert response.headers["cache-control"] == "no-store"
    await session.refresh(admin)
    assert admin.last_login_at is not None

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == str(admin.id)
    assert claims["aud"] == "identity-api"
    assert claims["roles"] == ["vendor_reviewer"]
    assert "must_change_password" not in claims


async def test_login_email_is_case_insensitive(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    assert (await login(client, "  Reviewer@Shazlo.TEST ")).status_code == 200


async def test_access_token_is_accepted_by_a_protected_endpoint(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    response = await client.get("/v1/protected", headers=bearer(await login(client)))
    assert response.status_code == 200
    assert response.json() == {"email": "reviewer@shazlo.test"}


async def test_refresh_cookie_attributes(client: httpx.AsyncClient, make_admin: MakeAdmin) -> None:
    await make_admin()
    cookie = refresh_cookie(await login(client))
    assert cookie is not None
    assert cookie["httponly"] is True
    assert cookie["secure"] is True
    assert cookie["samesite"].lower() == "strict"
    assert cookie["path"] == "/v1/auth"
    assert cookie["expires"]


async def test_cookie_flags_follow_settings(
    api_settings: Settings,
    override: Callable[..., Settings],
    session: AsyncSession,
    redis: FakeAsyncRedis,
    make_admin: MakeAdmin,
) -> None:
    await make_admin()
    settings = override(
        api_settings, cookie_secure=False, cookie_samesite="lax", cookie_domain="shazlo.test"
    )
    app = create_app(settings, readiness_checks={}, redis=redis)

    async def test_session() -> AsyncIterator[AsyncSession]:
        yield session

    app.dependency_overrides[get_session] = test_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://identity.test"
    ) as http:
        cookie = refresh_cookie(await login(http))
    assert cookie is not None
    assert not cookie["secure"]
    assert cookie["samesite"].lower() == "lax"
    assert cookie["domain"] == "shazlo.test"
    assert cookie["httponly"] is True


async def test_refresh_token_is_never_in_the_body(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    response = await login(client)
    token = refresh_token(response)
    assert token not in response.text
    refreshed = await refresh_with(client, token)
    assert refresh_token(refreshed) not in refreshed.text
    assert "refresh" not in json.dumps(list(refreshed.json())).lower()


@pytest.mark.parametrize(
    ("email", "password", "active"),
    [
        ("reviewer@shazlo.test", "wrong password!!", True),
        ("nobody@shazlo.test", PASSWORD, True),
        ("reviewer@shazlo.test", PASSWORD, False),
    ],
    ids=["wrong-password", "unknown-email", "inactive"],
)
async def test_failed_logins_are_indistinguishable(
    client: httpx.AsyncClient, make_admin: MakeAdmin, email: str, password: str, active: bool
) -> None:
    await make_admin(is_active=active)
    response = await client.post("/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 401
    error = response.json()["error"]
    assert (error["code"], error["message"]) == ("invalid_credentials", "Invalid email or password")
    assert refresh_cookie(response) is None


# --- must change password ------------------------------------------------------------------


async def test_must_change_password_limits_the_token(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin(must_change_password=True, role="super_admin")
    response = await login(client)
    assert response.status_code == 200
    assert response.json()["must_change_password"] is True
    claims = jwt.decode(response.json()["access_token"], options={"verify_signature": False})
    assert claims["roles"] == []
    assert claims["must_change_password"] is True

    blocked = await client.get("/v1/protected", headers=bearer(response))
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"


async def test_change_password_unblocks_the_admin(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin(must_change_password=True)
    first = await login(client)
    changed = await client.post(
        "/v1/auth/change-password",
        headers=bearer(first),
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert changed.status_code == 200
    assert changed.json()["must_change_password"] is False
    claims = jwt.decode(changed.json()["access_token"], options={"verify_signature": False})
    assert claims["roles"] == ["vendor_reviewer"]
    assert (await client.get("/v1/protected", headers=bearer(changed))).status_code == 200

    # The old password is gone and the new one works.
    old = await client.post(
        "/v1/auth/login", json={"email": "reviewer@shazlo.test", "password": PASSWORD}
    )
    assert old.status_code == 401
    new = await client.post(
        "/v1/auth/login", json={"email": "reviewer@shazlo.test", "password": NEW_PASSWORD}
    )
    assert new.status_code == 200
    assert new.json()["must_change_password"] is False


# --- refresh -------------------------------------------------------------------------------


async def test_refresh_rotates_the_token(client: httpx.AsyncClient, make_admin: MakeAdmin) -> None:
    await make_admin()
    first = refresh_token(await login(client))
    response = await refresh_with(client, first)
    assert response.status_code == 200
    second = refresh_token(response)
    assert second != first
    assert response.headers["cache-control"] == "no-store"
    assert (await client.get("/v1/protected", headers=bearer(response))).status_code == 200
    # The rotated token works in turn.
    assert (await refresh_with(client, second)).status_code == 200


async def test_reusing_a_rotated_token_revokes_the_family(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    first = refresh_token(await login(client))
    second = refresh_token(await refresh_with(client, first))

    reuse = await refresh_with(client, first)
    assert reuse.status_code == 401
    assert reuse.json()["error"]["code"] == "invalid_refresh_token"
    # The next refresh fails too, even with the token that was legitimately issued.
    assert (await refresh_with(client, second)).status_code == 401


async def test_only_the_hash_is_stored_in_redis(
    client: httpx.AsyncClient, make_admin: MakeAdmin, redis: FakeAsyncRedis
) -> None:
    await make_admin()
    token = refresh_token(await login(client))
    keys = [key.decode() if isinstance(key, bytes) else key async for key in redis.scan_iter("*")]
    assert f"rt:{hash_token(token)}" in keys
    assert all(token not in key for key in keys)


async def test_refresh_without_a_cookie_fails_and_clears_it(client: httpx.AsyncClient) -> None:
    client.cookies.clear()
    response = await client.post("/v1/auth/refresh")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_refresh_token"
    cleared = refresh_cookie(response)
    assert cleared is not None
    assert cleared.value == ""
    assert cleared["path"] == "/v1/auth"
    assert cleared["max-age"] == "0"


async def test_unknown_refresh_token_fails(client: httpx.AsyncClient) -> None:
    assert (await refresh_with(client, "made-up-token")).status_code == 401


async def test_expired_family_cannot_refresh(
    client: httpx.AsyncClient, make_admin: MakeAdmin, redis: FakeAsyncRedis
) -> None:
    await make_admin()
    token = refresh_token(await login(client))
    family_key = await anext(redis.scan_iter("rf:*"))
    # Past the 30 day limit, even though the key has not been evicted yet.
    await redis.hset(family_key, "expires_at", "1000")
    assert (await refresh_with(client, token)).status_code == 401


async def test_deactivated_admin_cannot_refresh(
    client: httpx.AsyncClient, make_admin: MakeAdmin, session: AsyncSession
) -> None:
    admin = await make_admin()
    token = refresh_token(await login(client))
    admin.is_active = False
    await session.commit()

    assert (await refresh_with(client, token)).status_code == 401
    # The family was revoked, so reactivating the admin does not revive the session.
    admin.is_active = True
    await session.commit()
    assert (await refresh_with(client, token)).status_code == 401


async def test_deactivated_admin_token_is_rejected_by_protected_endpoints(
    client: httpx.AsyncClient, make_admin: MakeAdmin, session: AsyncSession
) -> None:
    admin = await make_admin()
    headers = bearer(await login(client))
    admin.is_active = False
    await session.commit()
    assert (await client.get("/v1/protected", headers=headers)).status_code == 401


async def test_role_changes_apply_on_refresh(
    client: httpx.AsyncClient, make_admin: MakeAdmin, session: AsyncSession
) -> None:
    admin = await make_admin()
    token = refresh_token(await login(client))
    admin.roles = [await session.get_one(Role, "super_admin")]
    await session.commit()
    refreshed = await refresh_with(client, token)
    assert refreshed.json()["admin"]["roles"] == ["super_admin"]
    claims = jwt.decode(refreshed.json()["access_token"], options={"verify_signature": False})
    assert claims["roles"] == ["super_admin"]


# --- logout --------------------------------------------------------------------------------


async def test_logout_revokes_the_family_and_clears_the_cookie(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    token = refresh_token(await login(client))
    client.cookies.clear()
    response = await client.post("/v1/auth/logout", headers={"Cookie": f"refresh_token={token}"})
    assert response.status_code == 204
    cleared = refresh_cookie(response)
    assert cleared is not None
    assert cleared.value == ""
    assert cleared["max-age"] == "0"
    assert (await refresh_with(client, token)).status_code == 401


async def test_logout_without_a_session_is_fine(client: httpx.AsyncClient) -> None:
    client.cookies.clear()
    assert (await client.post("/v1/auth/logout")).status_code == 204


async def test_logout_ends_only_its_own_family(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    laptop = refresh_token(await login(client))
    phone = refresh_token(await login(client))
    client.cookies.clear()
    await client.post("/v1/auth/logout", headers={"Cookie": f"refresh_token={laptop}"})
    assert (await refresh_with(client, laptop)).status_code == 401
    assert (await refresh_with(client, phone)).status_code == 200


# --- change password -----------------------------------------------------------------------


async def test_change_password_revokes_other_families_and_starts_a_new_one(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    other_device = refresh_token(await login(client))
    here = await login(client)
    old_refresh = refresh_token(here)

    changed = await client.post(
        "/v1/auth/change-password",
        headers=bearer(here),
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert changed.status_code == 200
    assert (await refresh_with(client, other_device)).status_code == 401
    assert (await refresh_with(client, old_refresh)).status_code == 401
    # The session started by the change keeps working.
    assert (await refresh_with(client, refresh_token(changed))).status_code == 200


async def test_change_password_needs_the_current_password(
    client: httpx.AsyncClient, make_admin: MakeAdmin
) -> None:
    await make_admin()
    response = await client.post(
        "/v1/auth/change-password",
        headers=bearer(await login(client)),
        json={"current_password": "not the password", "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_current_password"


@pytest.mark.parametrize(
    "new_password", ["short", PASSWORD, "reviewer@shazlo.test"], ids=["short", "same", "email"]
)
async def test_change_password_enforces_the_policy(
    client: httpx.AsyncClient, make_admin: MakeAdmin, new_password: str
) -> None:
    await make_admin()
    response = await client.post(
        "/v1/auth/change-password",
        headers=bearer(await login(client)),
        json={"current_password": PASSWORD, "new_password": new_password},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "weak_password"
    assert new_password not in response.text


async def test_change_password_needs_an_access_token(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


# --- tokens, CORS, logs --------------------------------------------------------------------


@pytest.mark.parametrize("header", ["Bearer garbage", "Basic abc", "Bearer "])
async def test_bad_bearer_tokens_are_rejected(client: httpx.AsyncClient, header: str) -> None:
    response = await client.get("/v1/protected", headers={"Authorization": header})
    assert response.status_code == 401


async def test_cors_allows_only_configured_origins(client: httpx.AsyncClient) -> None:
    def preflight(origin: str) -> Any:
        return client.options(
            "/v1/auth/login",
            headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
        )

    allowed = await preflight(ORIGIN)
    assert allowed.headers["access-control-allow-origin"] == ORIGIN
    assert allowed.headers["access-control-allow-credentials"] == "true"

    denied = await preflight("https://evil.test")
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers

    simple = await client.post(
        "/v1/auth/login",
        json={"email": "a@b.test", "password": "x"},
        headers={"Origin": "https://evil.test"},
    )
    assert "access-control-allow-origin" not in simple.headers


async def test_tokens_are_never_logged(
    client: httpx.AsyncClient, make_admin: MakeAdmin, caplog: pytest.LogCaptureFixture
) -> None:
    await make_admin()
    caplog.set_level(logging.DEBUG)
    response = await login(client)
    token = refresh_token(response)
    await refresh_with(client, token)
    await refresh_with(client, token)  # reuse is logged as a warning
    assert caplog.records
    for record in caplog.records:
        text = json.dumps(record.__dict__, default=str)
        assert token not in text
        assert response.json()["access_token"] not in text
    assert any("reuse" in record.getMessage() for record in caplog.records)

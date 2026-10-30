import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import jwt
import pytest
from fakeredis import FakeAsyncRedis
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.app import create_app
from identity_api.core.settings import Settings
from identity_api.db.models import Admin, Role
from identity_api.db.session import get_session
from identity_api.services.passwords import PasswordService

PASSWORD = "correct horse battery"
EMAIL = "reviewer@shazlo.test"
ISSUER = "https://identity.test"

# A service that only super_admin may use, to show what "nothing else" means.
AUDIENCE_ROLES = {
    "identity-api": ["super_admin", "vendor_reviewer"],
    "vendor-api": ["super_admin", "vendor_reviewer"],
    "billing-api": ["super_admin"],
}


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    client = FakeAsyncRedis()
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
def api_settings(settings: Settings, override: Callable[..., Settings]) -> Settings:
    return override(
        settings,
        jwt_issuer=ISSUER,
        audience_roles=AUDIENCE_ROLES,
        argon2_memory_cost_kib=8,
        argon2_time_cost=1,
    )


@pytest.fixture
async def client(
    api_settings: Settings, session: AsyncSession, redis: FakeAsyncRedis
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(api_settings, readiness_checks={}, redis=redis)

    async def test_session() -> AsyncIterator[AsyncSession]:
        yield session

    app.dependency_overrides[get_session] = test_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://identity.test"
    ) as http:
        yield http


async def make_admin(
    session: AsyncSession,
    settings: Settings,
    *,
    roles: tuple[str, ...] = ("vendor_reviewer",),
    must_change_password: bool = False,
) -> Admin:
    admin = Admin(
        email=EMAIL,
        password_hash=await PasswordService(settings).hash(PASSWORD),
        display_name="Test Admin",
        must_change_password=must_change_password,
        roles=[await session.get_one(Role, name) for name in roles],
    )
    session.add(admin)
    await session.commit()
    return admin


async def sign_in(client: httpx.AsyncClient) -> dict[str, str]:
    response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def exchange(client: httpx.AsyncClient, headers: dict[str, str], audience: str) -> Any:
    return await client.post("/v1/auth/token", headers=headers, json={"audience": audience})


def claims_of(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False})


@pytest.mark.parametrize("audience", ["vendor-api", "identity-api"])
async def test_reviewer_gets_tokens_for_their_audiences(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings, audience: str
) -> None:
    admin = await make_admin(session, api_settings)
    response = await exchange(client, await sign_in(client), audience)
    assert response.status_code == 200
    body = response.json()
    assert body["audience"] == audience
    assert body["expires_in"] == 900
    assert set(body) == {"access_token", "token_type", "expires_in", "audience"}
    assert response.headers["cache-control"] == "no-store"
    assert "refresh_token" not in response.headers.get("set-cookie", "")

    claims = claims_of(body["access_token"])
    assert claims["aud"] == audience  # a single string, never a list
    assert claims["sub"] == str(admin.id)
    assert claims["roles"] == ["vendor_reviewer"]
    assert claims["iss"] == ISSUER
    assert claims["exp"] - claims["iat"] == 900
    assert {"jti"} <= claims.keys()
    assert not {"email", "name", "display_name"} & claims.keys()
    assert jwt.get_unverified_header(body["access_token"])["kid"] == "test-key-1"


async def test_reviewer_cannot_get_other_audiences(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    await make_admin(session, api_settings)
    response = await exchange(client, await sign_in(client), "billing-api")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "audience_not_allowed"


async def test_super_admin_gets_every_audience(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    await make_admin(session, api_settings, roles=("super_admin",))
    headers = await sign_in(client)
    for audience in AUDIENCE_ROLES:
        assert (await exchange(client, headers, audience)).status_code == 200


async def test_unknown_audience_is_a_bad_request(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    await make_admin(session, api_settings)
    response = await exchange(client, await sign_in(client), "nope-api")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "unknown_audience"


@pytest.mark.parametrize("body", [{}, {"audience": ""}, {"audience": ["vendor-api"]}])
async def test_audience_must_be_one_non_empty_string(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings, body: dict[str, Any]
) -> None:
    await make_admin(session, api_settings)
    response = await client.post("/v1/auth/token", headers=await sign_in(client), json=body)
    assert response.status_code == 422


async def test_exchange_needs_a_valid_token(client: httpx.AsyncClient) -> None:
    assert (await exchange(client, {}, "vendor-api")).status_code == 401
    bad = {"Authorization": "Bearer garbage"}
    assert (await exchange(client, bad, "vendor-api")).status_code == 401


async def test_pending_password_admin_cannot_exchange(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    await make_admin(session, api_settings, must_change_password=True)
    response = await exchange(client, await sign_in(client), "vendor-api")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "password_change_required"


async def test_a_module_token_is_rejected_by_identity_api_itself(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    await make_admin(session, api_settings)
    module = await exchange(client, await sign_in(client), "vendor-api")
    headers = {"Authorization": f"Bearer {module.json()['access_token']}"}
    me = await client.get("/v1/me", headers=headers)
    assert me.status_code == 401
    assert (await exchange(client, headers, "vendor-api")).status_code == 401


async def test_exchange_uses_current_roles_and_active_status(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    admin = await make_admin(session, api_settings)
    headers = await sign_in(client)
    admin.roles = [await session.get_one(Role, "super_admin")]
    await session.commit()
    response = await exchange(client, headers, "billing-api")
    assert response.status_code == 200
    assert claims_of(response.json()["access_token"])["roles"] == ["super_admin"]

    admin.is_active = False
    await session.commit()
    assert (await exchange(client, headers, "vendor-api")).status_code == 401


async def test_me_returns_the_profile_only(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    admin = await make_admin(session, api_settings)
    headers = await sign_in(client)
    response = await client.get("/v1/me", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "id": str(admin.id),
        "email": EMAIL,
        "display_name": "Test Admin",
        "roles": ["vendor_reviewer"],
        "must_change_password": False,
    }
    assert response.headers["cache-control"] == "no-store"
    text = response.text.lower()
    assert admin.password_hash not in text
    assert "argon2" not in text
    assert headers["Authorization"].removeprefix("Bearer ") not in text


async def test_me_needs_a_token_and_a_changed_password(
    client: httpx.AsyncClient, session: AsyncSession, api_settings: Settings
) -> None:
    assert (await client.get("/v1/me")).status_code == 401
    await make_admin(session, api_settings, must_change_password=True)
    response = await client.get("/v1/me", headers=await sign_in(client))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "password_change_required"


async def test_adding_a_service_is_a_settings_change_only(
    api_settings: Settings,
    override: Callable[..., Settings],
    session: AsyncSession,
    redis: FakeAsyncRedis,
) -> None:
    await make_admin(session, api_settings)
    extended = override(
        api_settings, audience_roles={**AUDIENCE_ROLES, "orders-api": ["vendor_reviewer"]}
    )
    app = create_app(extended, readiness_checks={}, redis=redis)

    async def test_session() -> AsyncIterator[AsyncSession]:
        yield session

    app.dependency_overrides[get_session] = test_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://identity.test"
    ) as http:
        response = await exchange(http, await sign_in(http), "orders-api")
    assert response.status_code == 200
    assert claims_of(response.json()["access_token"])["aud"] == "orders-api"


def test_audience_roles_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIENCE_ROLES", json.dumps(AUDIENCE_ROLES))
    parsed = Settings(
        _env_file=None,
        database_url="postgresql://u:p@localhost/db",
        redis_url="redis://localhost:6379/0",
    )
    assert parsed.audience_roles == AUDIENCE_ROLES


@pytest.mark.parametrize(
    "value",
    [{"vendor-api": ["super_admin"]}, {"identity-api": []}, {"identity-api": ["a"], "": ["a"]}],
    ids=["no-identity-api", "no-roles", "empty-name"],
)
def test_invalid_audience_maps_are_rejected(value: dict[str, list[str]]) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            database_url="postgresql://u:p@localhost/db",
            redis_url="redis://localhost:6379/0",
            audience_roles=value,
        )

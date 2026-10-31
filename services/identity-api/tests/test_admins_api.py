import uuid
from collections.abc import AsyncIterator, Callable
from http.cookies import SimpleCookie
from typing import Any

import httpx
import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.app import create_app
from identity_api.core.settings import Settings
from identity_api.db.models import Admin, Role
from identity_api.db.session import get_session
from identity_api.services.passwords import PasswordService

PASSWORD = "correct horse battery"
BOSS = "boss@shazlo.test"
REVIEWER = "reviewer@shazlo.test"
NEW_PASSWORD = "an initial password"


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
        jwt_issuer="https://identity.test",
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


@pytest.fixture
def make_admin(session: AsyncSession, api_settings: Settings) -> Callable[..., Any]:
    async def make(
        email: str = REVIEWER,
        *,
        roles: tuple[str, ...] = ("vendor_reviewer",),
        is_active: bool = True,
        display_name: str = "Test Admin",
    ) -> Admin:
        admin = Admin(
            email=email,
            password_hash=await PasswordService(api_settings).hash(PASSWORD),
            display_name=display_name,
            is_active=is_active,
            must_change_password=False,
            roles=[await session.get_one(Role, name) for name in roles],
        )
        session.add(admin)
        await session.commit()
        return admin

    return make


async def login(client: httpx.AsyncClient, email: str) -> httpx.Response:
    client.cookies.clear()
    response = await client.post("/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200
    return response


def bearer(response: httpx.Response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def refresh_token(response: httpx.Response) -> str:
    for header in response.headers.get_list("set-cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(header)
        if "refresh_token" in cookie:
            return cookie["refresh_token"].value
    raise AssertionError("no refresh cookie")


async def refresh_with(client: httpx.AsyncClient, token: str) -> httpx.Response:
    client.cookies.clear()
    return await client.post("/v1/auth/refresh", headers={"Cookie": f"refresh_token={token}"})


@pytest.fixture
async def boss(make_admin: Callable[..., Any], client: httpx.AsyncClient) -> dict[str, str]:
    """A signed-in super_admin: the headers for the calls under test."""
    await make_admin(BOSS, roles=("super_admin",), display_name="Boss")
    return bearer(await login(client, BOSS))


def new_admin_body(**changes: Any) -> dict[str, Any]:
    return {
        "email": "new@shazlo.test",
        "display_name": "New Admin",
        "password": NEW_PASSWORD,
        "roles": ["vendor_reviewer"],
        **changes,
    }


# --- Permissions -------------------------------------------------------------------------


def endpoints(admin_id: uuid.UUID) -> list[tuple[str, str, dict[str, Any] | None]]:
    return [
        ("GET", "/v1/roles", None),
        ("GET", "/v1/admins", None),
        ("POST", "/v1/admins", new_admin_body()),
        ("GET", f"/v1/admins/{admin_id}", None),
        ("PATCH", f"/v1/admins/{admin_id}", {"display_name": "Changed"}),
        ("POST", f"/v1/admins/{admin_id}/reset-password", {"new_password": NEW_PASSWORD}),
    ]


async def test_no_token_is_401_everywhere(client: httpx.AsyncClient) -> None:
    for method, path, body in endpoints(uuid.uuid4()):
        response = await client.request(method, path, json=body)
        assert response.status_code == 401, (method, path)


async def test_non_super_admin_gets_403_everywhere(
    client: httpx.AsyncClient, make_admin: Callable[..., Any]
) -> None:
    reviewer = await make_admin()
    headers = bearer(await login(client, REVIEWER))
    for method, path, body in endpoints(reviewer.id):
        response = await client.request(method, path, headers=headers, json=body)
        assert response.status_code == 403, (method, path)
        assert response.json()["error"]["code"] == "forbidden"


async def test_403_comes_before_validation_and_lookup(
    client: httpx.AsyncClient, make_admin: Callable[..., Any]
) -> None:
    await make_admin()
    headers = bearer(await login(client, REVIEWER))
    invalid = await client.post("/v1/admins", headers=headers, json={"email": "nope"})
    assert invalid.status_code == 403
    missing = await client.get(f"/v1/admins/{uuid.uuid4()}", headers=headers)
    assert missing.status_code == 403


async def test_a_role_change_applies_at_once_to_this_api(
    client: httpx.AsyncClient, make_admin: Callable[..., Any], session: AsyncSession
) -> None:
    """The token still says super_admin, but roles are read from the database."""
    boss = await make_admin(BOSS, roles=("super_admin",))
    await make_admin("other@shazlo.test", roles=("super_admin",))
    headers = bearer(await login(client, BOSS))
    boss.roles = [await session.get_one(Role, "vendor_reviewer")]
    await session.commit()
    assert (await client.get("/v1/admins", headers=headers)).status_code == 403


async def test_deactivated_super_admin_token_stops_working(
    client: httpx.AsyncClient, make_admin: Callable[..., Any], session: AsyncSession
) -> None:
    boss = await make_admin(BOSS, roles=("super_admin",))
    headers = bearer(await login(client, BOSS))
    boss.is_active = False
    await session.commit()
    assert (await client.get("/v1/admins", headers=headers)).status_code == 401


# --- Roles -------------------------------------------------------------------------------


async def test_list_roles(client: httpx.AsyncClient, boss: dict[str, str]) -> None:
    response = await client.get("/v1/roles", headers=boss)
    assert response.status_code == 200
    roles = response.json()
    assert [role["name"] for role in roles] == ["super_admin", "vendor_reviewer"]
    assert all(set(role) == {"name", "description"} for role in roles)


# --- Create ------------------------------------------------------------------------------


async def test_create_admin(client: httpx.AsyncClient, boss: dict[str, str]) -> None:
    response = await client.post("/v1/admins", headers=boss, json=new_admin_body())
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new@shazlo.test"
    assert body["display_name"] == "New Admin"
    assert body["roles"] == ["vendor_reviewer"]
    assert body["is_active"] is True
    assert body["must_change_password"] is True
    assert body["last_login_at"] is None
    assert response.headers["location"] == f"/v1/admins/{body['id']}"
    assert not {"password", "password_hash"} & body.keys()
    assert NEW_PASSWORD not in response.text


async def test_created_admin_signs_in_but_must_change_the_password(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    await client.post("/v1/admins", headers=boss, json=new_admin_body())
    client.cookies.clear()
    response = await client.post(
        "/v1/auth/login", json={"email": "new@shazlo.test", "password": NEW_PASSWORD}
    )
    assert response.status_code == 200
    assert response.json()["must_change_password"] is True
    blocked = await client.get("/v1/me", headers=bearer(response))
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"


@pytest.mark.parametrize("email", ["NEW@shazlo.test", " new@shazlo.test ", "New@Shazlo.Test"])
async def test_duplicate_email_in_any_letter_case_is_409(
    client: httpx.AsyncClient, boss: dict[str, str], email: str
) -> None:
    assert (await client.post("/v1/admins", headers=boss, json=new_admin_body())).status_code == 201
    response = await client.post("/v1/admins", headers=boss, json=new_admin_body(email=email))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "email_taken"


async def test_email_is_stored_lower_case(client: httpx.AsyncClient, boss: dict[str, str]) -> None:
    response = await client.post(
        "/v1/admins", headers=boss, json=new_admin_body(email="Mixed.Case@Shazlo.Test")
    )
    assert response.json()["email"] == "mixed.case@shazlo.test"


async def test_duplicate_of_the_seeded_super_admin_is_409(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    response = await client.post(
        "/v1/admins", headers=boss, json=new_admin_body(email=BOSS.upper())
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("changes", "status", "code"),
    [
        ({"roles": ["no_such_role"]}, 422, "unknown_role"),
        ({"roles": ["vendor_reviewer", "no_such_role"]}, 422, "unknown_role"),
        ({"password": "short"}, 422, "weak_password"),
        ({"password": "x" * 129}, 422, "validation_error"),
        ({"password": NEW_PASSWORD, "email": "not-an-email"}, 422, "validation_error"),
        ({"roles": []}, 422, "validation_error"),
        ({"display_name": ""}, 422, "validation_error"),
    ],
)
async def test_create_rejects_bad_input(
    client: httpx.AsyncClient, boss: dict[str, str], changes: dict[str, Any], status: int, code: str
) -> None:
    response = await client.post("/v1/admins", headers=boss, json=new_admin_body(**changes))
    assert response.status_code == status
    assert response.json()["error"]["code"] == code


async def test_password_equal_to_email_is_rejected(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    email = "same.as.password@shazlo.test"
    response = await client.post(
        "/v1/admins", headers=boss, json=new_admin_body(email=email, password=email)
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "weak_password"


async def test_duplicate_roles_in_the_request_are_collapsed(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    response = await client.post(
        "/v1/admins", headers=boss, json=new_admin_body(roles=["vendor_reviewer"] * 2)
    )
    assert response.status_code == 201
    assert response.json()["roles"] == ["vendor_reviewer"]


# --- List and get ------------------------------------------------------------------------


async def seed_many(make_admin: Callable[..., Any]) -> None:
    await make_admin("alice@shazlo.test", display_name="Alice Archer")
    await make_admin("bob@shazlo.test", display_name="Bob Baker", is_active=False)
    await make_admin("carol@shazlo.test", roles=("super_admin",), display_name="Carol 100%")
    await make_admin("dave@shazlo.test", display_name="Dave_Day")


async def test_list_admins_with_pagination(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    await seed_many(make_admin)  # five admins with the one that made the call
    first = (await client.get("/v1/admins?limit=2", headers=boss)).json()
    assert (first["total"], first["limit"], first["offset"]) == (5, 2, 0)
    second = (await client.get("/v1/admins?limit=2&offset=2", headers=boss)).json()
    last = (await client.get("/v1/admins?limit=2&offset=4", headers=boss)).json()
    emails = [a["email"] for page in (first, second, last) for a in page["items"]]
    assert len(emails) == 5
    assert len(set(emails)) == 5  # no repeats or gaps across pages
    assert len(last["items"]) == 1


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "offset=-1", "limit=abc"])
async def test_list_rejects_bad_paging(
    client: httpx.AsyncClient, boss: dict[str, str], query: str
) -> None:
    response = await client.get(f"/v1/admins?{query}", headers=boss)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("role=super_admin", {BOSS, "carol@shazlo.test"}),
        ("role=vendor_reviewer", {"alice@shazlo.test", "bob@shazlo.test", "dave@shazlo.test"}),
        ("is_active=false", {"bob@shazlo.test"}),
        ("is_active=true&role=vendor_reviewer", {"alice@shazlo.test", "dave@shazlo.test"}),
        ("q=ALICE", {"alice@shazlo.test"}),
        ("q=baker", {"bob@shazlo.test"}),
        ("q=%25", {"carol@shazlo.test"}),  # a literal "%", not a wildcard
        ("q=_", {"dave@shazlo.test"}),  # a literal "_", not a wildcard
        ("q=nobody", set()),
        ("role=no_such_role", set()),
    ],
)
async def test_list_filters(
    client: httpx.AsyncClient,
    boss: dict[str, str],
    make_admin: Callable[..., Any],
    query: str,
    expected: set[str],
) -> None:
    await seed_many(make_admin)
    body = (await client.get(f"/v1/admins?{query}", headers=boss)).json()
    assert {admin["email"] for admin in body["items"]} == expected
    assert body["total"] == len(expected)


async def test_get_admin(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    response = await client.get(f"/v1/admins/{admin.id}", headers=boss)
    assert response.status_code == 200
    assert response.json()["email"] == REVIEWER
    assert response.headers["cache-control"] == "no-store"
    assert "password_hash" not in response.json()


async def test_get_unknown_admin_is_404(client: httpx.AsyncClient, boss: dict[str, str]) -> None:
    response = await client.get(f"/v1/admins/{uuid.uuid4()}", headers=boss)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "admin_not_found"


async def test_malformed_admin_id_is_422(client: httpx.AsyncClient, boss: dict[str, str]) -> None:
    assert (await client.get("/v1/admins/not-a-uuid", headers=boss)).status_code == 422


# --- Update ------------------------------------------------------------------------------


async def test_patch_name_and_roles(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    response = await client.patch(
        f"/v1/admins/{admin.id}",
        headers=boss,
        json={"display_name": "  Renamed  ", "roles": ["super_admin", "vendor_reviewer"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["display_name"] == "Renamed"
    assert body["roles"] == ["super_admin", "vendor_reviewer"]
    assert body["is_active"] is True


async def test_patch_only_changes_what_is_sent(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    response = await client.patch(f"/v1/admins/{admin.id}", headers=boss, json={})
    assert response.status_code == 200
    assert response.json()["display_name"] == "Test Admin"
    assert response.json()["roles"] == ["vendor_reviewer"]


async def test_patch_unknown_role_or_admin(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    bad_role = await client.patch(f"/v1/admins/{admin.id}", headers=boss, json={"roles": ["x"]})
    assert bad_role.status_code == 422
    assert bad_role.json()["error"]["code"] == "unknown_role"
    missing = await client.patch(
        f"/v1/admins/{uuid.uuid4()}", headers=boss, json={"is_active": False}
    )
    assert missing.status_code == 404


async def test_a_role_change_shows_in_the_next_exchanged_token(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    await client.patch(f"/v1/admins/{admin.id}", headers=boss, json={"roles": ["super_admin"]})
    # The role is read when the next token is issued, so a fresh login carries it.
    response = await login(client, REVIEWER)
    assert response.json()["admin"]["roles"] == ["super_admin"]


async def test_reactivating_an_admin(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin(is_active=False)
    response = await client.patch(f"/v1/admins/{admin.id}", headers=boss, json={"is_active": True})
    assert response.status_code == 200
    assert response.json()["is_active"] is True
    assert (await login(client, REVIEWER)).status_code == 200


# --- Session revocation ------------------------------------------------------------------


async def test_deactivating_revokes_every_refresh_family(
    client: httpx.AsyncClient,
    boss: dict[str, str],
    make_admin: Callable[..., Any],
    redis: FakeAsyncRedis,
) -> None:
    admin = await make_admin()
    tokens = [refresh_token(await login(client, REVIEWER)) for _ in range(3)]
    assert await redis.scard(f"ra:{admin.id}") == 3

    response = await client.patch(f"/v1/admins/{admin.id}", headers=boss, json={"is_active": False})
    assert response.status_code == 200

    assert await redis.exists(f"ra:{admin.id}") == 0
    assert [key async for key in redis.scan_iter("rf:*")] == []
    for token in tokens:
        refreshed = await refresh_with(client, token)
        assert refreshed.status_code == 401
        assert refreshed.json()["error"]["code"] == "invalid_refresh_token"
    assert (
        await client.post("/v1/auth/login", json={"email": REVIEWER, "password": PASSWORD})
    ).status_code == 401


async def test_deactivating_one_admin_leaves_other_sessions(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    await make_admin("other@shazlo.test")
    other_token = refresh_token(await login(client, "other@shazlo.test"))
    await client.patch(f"/v1/admins/{admin.id}", headers=boss, json={"is_active": False})
    assert (await refresh_with(client, other_token)).status_code == 200


async def test_renaming_or_changing_roles_keeps_sessions(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    admin = await make_admin()
    token = refresh_token(await login(client, REVIEWER))
    await client.patch(
        f"/v1/admins/{admin.id}",
        headers=boss,
        json={"display_name": "New", "roles": ["super_admin"]},
    )
    assert (await refresh_with(client, token)).status_code == 200


async def test_reset_password(
    client: httpx.AsyncClient,
    boss: dict[str, str],
    make_admin: Callable[..., Any],
    redis: FakeAsyncRedis,
) -> None:
    admin = await make_admin()
    token = refresh_token(await login(client, REVIEWER))

    response = await client.post(
        f"/v1/admins/{admin.id}/reset-password", headers=boss, json={"new_password": NEW_PASSWORD}
    )
    assert response.status_code == 204
    assert response.content == b""
    assert await redis.exists(f"ra:{admin.id}") == 0
    assert (await refresh_with(client, token)).status_code == 401

    client.cookies.clear()
    old = await client.post("/v1/auth/login", json={"email": REVIEWER, "password": PASSWORD})
    assert old.status_code == 401
    new = await client.post("/v1/auth/login", json={"email": REVIEWER, "password": NEW_PASSWORD})
    assert new.status_code == 200
    assert new.json()["must_change_password"] is True


@pytest.mark.parametrize(
    ("password", "status", "code"),
    [("short", 422, "weak_password"), ("x" * 129, 422, "validation_error")],
)
async def test_reset_password_applies_the_policy(
    client: httpx.AsyncClient,
    boss: dict[str, str],
    make_admin: Callable[..., Any],
    password: str,
    status: int,
    code: str,
) -> None:
    admin = await make_admin()
    token = refresh_token(await login(client, REVIEWER))
    response = await client.post(
        f"/v1/admins/{admin.id}/reset-password", headers=boss, json={"new_password": password}
    )
    assert (response.status_code, response.json()["error"]["code"]) == (status, code)
    # A rejected reset changes nothing.
    assert (await refresh_with(client, token)).status_code == 200


async def test_reset_password_of_unknown_admin_is_404(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    response = await client.post(
        f"/v1/admins/{uuid.uuid4()}/reset-password",
        headers=boss,
        json={"new_password": NEW_PASSWORD},
    )
    assert response.status_code == 404


# --- Guards ------------------------------------------------------------------------------


async def test_an_admin_cannot_deactivate_themselves(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    await make_admin("second@shazlo.test", roles=("super_admin",))
    me = (await client.get("/v1/me", headers=boss)).json()
    response = await client.patch(f"/v1/admins/{me['id']}", headers=boss, json={"is_active": False})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "cannot_deactivate_self"
    assert (await client.get("/v1/me", headers=boss)).json()["id"] == me["id"]


async def test_the_last_super_admin_cannot_lose_the_role(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    me = (await client.get("/v1/me", headers=boss)).json()
    response = await client.patch(
        f"/v1/admins/{me['id']}", headers=boss, json={"roles": ["vendor_reviewer"]}
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "last_super_admin"
    assert (await client.get("/v1/me", headers=boss)).json()["roles"] == ["super_admin"]


async def test_the_last_active_super_admin_counts_only_active_ones(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    """An inactive super_admin does not count, so the active one is the last."""
    await make_admin("inactive@shazlo.test", roles=("super_admin",), is_active=False)
    me = (await client.get("/v1/me", headers=boss)).json()
    response = await client.patch(
        f"/v1/admins/{me['id']}", headers=boss, json={"roles": ["vendor_reviewer"]}
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "last_super_admin"


async def test_a_super_admin_can_demote_another_while_one_remains(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    second = await make_admin("second@shazlo.test", roles=("super_admin",))
    response = await client.patch(
        f"/v1/admins/{second.id}", headers=boss, json={"roles": ["vendor_reviewer"]}
    )
    assert response.status_code == 200
    assert response.json()["roles"] == ["vendor_reviewer"]


async def test_a_super_admin_can_deactivate_another_while_one_remains(
    client: httpx.AsyncClient, boss: dict[str, str], make_admin: Callable[..., Any]
) -> None:
    second = await make_admin("second@shazlo.test", roles=("super_admin",))
    response = await client.patch(
        f"/v1/admins/{second.id}", headers=boss, json={"is_active": False}
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False


async def test_a_rejected_guard_changes_nothing(
    client: httpx.AsyncClient, boss: dict[str, str]
) -> None:
    """The guard answers before any field is applied, so a name change in the same call is lost."""
    me = (await client.get("/v1/me", headers=boss)).json()
    response = await client.patch(
        f"/v1/admins/{me['id']}",
        headers=boss,
        json={"display_name": "Renamed", "roles": ["vendor_reviewer"]},
    )
    assert response.status_code == 409
    assert (await client.get(f"/v1/admins/{me['id']}", headers=boss)).json()[
        "display_name"
    ] == "Boss"

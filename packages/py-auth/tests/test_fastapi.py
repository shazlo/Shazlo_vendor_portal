import uuid
from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI

from shazlo_auth import StaticKeySource, TokenVerifier
from shazlo_auth.fastapi import AuthenticatedAdmin, get_current_admin, require_role
from tests.helpers import ADMIN_ID, AUDIENCE, ISSUER

Sign = Callable[..., str]


@pytest.fixture
async def http(private_keys: dict[str, rsa.RSAPrivateKey]) -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.state.token_verifier = TokenVerifier(
        StaticKeySource({"key-1": private_keys["key-1"].public_key()}),
        issuer=ISSUER,
        audience=AUDIENCE,
    )

    @app.get("/me")
    async def me(admin: AuthenticatedAdmin = Depends(get_current_admin)) -> dict[str, object]:
        return {"id": str(admin.id), "roles": sorted(admin.roles)}

    @app.get("/reviews")
    async def reviews(admin: AuthenticatedAdmin = Depends(require_role("vendor_reviewer"))) -> str:
        return str(admin.id)

    @app.get("/either")
    async def either(
        admin: AuthenticatedAdmin = Depends(require_role("vendor_reviewer", "catalog_editor")),
    ) -> str:
        return str(admin.id)

    async def from_elsewhere() -> AuthenticatedAdmin:
        return AuthenticatedAdmin(uuid.UUID(int=7), frozenset({"vendor_reviewer"}))

    @app.get("/custom")
    async def custom(
        admin: AuthenticatedAdmin = Depends(require_role("vendor_reviewer", source=from_elsewhere)),
    ) -> str:
        return str(admin.id)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_the_admin_comes_from_the_token(http: httpx.AsyncClient, sign: Sign) -> None:
    response = await http.get("/me", headers=bearer(sign()))
    assert response.status_code == 200
    assert response.json() == {"id": str(ADMIN_ID), "roles": ["vendor_reviewer"]}


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"}]
)
async def test_no_usable_credentials_is_401(
    http: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    response = await http.get("/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_an_invalid_token_is_401(http: httpx.AsyncClient, sign: Sign) -> None:
    for token in ("garbage", sign(aud="other-api"), sign("key-1", key="key-2")):
        assert (await http.get("/me", headers=bearer(token))).status_code == 401


async def test_a_pending_password_token_is_403_even_for_get_current_admin(
    http: httpx.AsyncClient, sign: Sign
) -> None:
    response = await http.get("/me", headers=bearer(sign(roles=[], must_change_password=True)))
    assert response.status_code == 403


async def test_a_matching_role_passes(http: httpx.AsyncClient, sign: Sign) -> None:
    assert (await http.get("/reviews", headers=bearer(sign()))).status_code == 200


async def test_a_missing_role_is_403(http: httpx.AsyncClient, sign: Sign) -> None:
    for roles in ([], ["other_role"]):
        response = await http.get("/reviews", headers=bearer(sign(roles=roles)))
        assert response.status_code == 403


async def test_super_admin_always_passes(http: httpx.AsyncClient, sign: Sign) -> None:
    assert (
        await http.get("/reviews", headers=bearer(sign(roles=["super_admin"])))
    ).status_code == 200
    assert (
        await http.get("/either", headers=bearer(sign(roles=["super_admin"])))
    ).status_code == 200


async def test_any_one_of_several_roles_is_enough(http: httpx.AsyncClient, sign: Sign) -> None:
    assert (
        await http.get("/either", headers=bearer(sign(roles=["catalog_editor"])))
    ).status_code == 200
    assert (await http.get("/either", headers=bearer(sign(roles=["x"])))).status_code == 403


async def test_a_role_check_without_a_token_is_401_not_403(http: httpx.AsyncClient) -> None:
    assert (await http.get("/reviews")).status_code == 401


async def test_the_admin_can_come_from_another_source(http: httpx.AsyncClient) -> None:
    response = await http.get("/custom")  # no token needed: the source decides
    assert response.status_code == 200
    assert response.json() == str(uuid.UUID(int=7))


def test_require_role_needs_a_role() -> None:
    with pytest.raises(ValueError):
        require_role()

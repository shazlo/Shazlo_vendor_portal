"""FastAPI dependencies. Needs the `fastapi` extra.

The app provides its verifier once::

    keys = JwksClient.from_url("https://identity.shazlo.store/.well-known/jwks.json")
    app.state.token_verifier = TokenVerifier(keys, issuer=ISSUER, audience="vendor-api")

and routes ask for an admin or a role::

    @router.get("/reviews", dependencies=[Depends(require_role("vendor_reviewer"))])
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from shazlo_auth.errors import InvalidTokenError
from shazlo_auth.verifier import TokenVerifier

SUPER_ADMIN = "super_admin"

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedAdmin:
    """Who is calling. Identity comes from here and never from a body, query or header."""

    id: uuid.UUID
    roles: frozenset[str]
    jti: str | None = None


def unauthorized() -> HTTPException:
    return HTTPException(
        401, "Missing or invalid access token", headers={"WWW-Authenticate": "Bearer"}
    )


async def get_current_admin(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AuthenticatedAdmin:
    """The admin in a valid access token for this service, from `app.state.token_verifier`.

    A token that only allows a password change carries no roles and grants nothing here.
    """
    if credentials is None:
        raise unauthorized()
    verifier = cast(TokenVerifier, request.app.state.token_verifier)
    try:
        claims = await verifier.verify(credentials.credentials)
    except InvalidTokenError as error:
        raise unauthorized() from error
    if claims.must_change_password:
        raise HTTPException(403, "Change your password before using the API")
    return AuthenticatedAdmin(claims.subject, frozenset(claims.roles), claims.jti)


def require_role(
    *roles: str,
    source: Callable[..., Awaitable[AuthenticatedAdmin]] = get_current_admin,
) -> Callable[..., Awaitable[AuthenticatedAdmin]]:
    """The admin, who must hold at least one of `roles`. `super_admin` always passes.

    `source` is where the admin comes from. The default reads the access token. identity-api
    passes its own, which reads roles from its database so that a change applies at once.
    """
    if not roles:
        raise ValueError("require_role needs at least one role")
    allowed = frozenset(roles) | {SUPER_ADMIN}

    async def dependency(
        admin: Annotated[AuthenticatedAdmin, Depends(source)],
    ) -> AuthenticatedAdmin:
        if not admin.roles & allowed:
            raise HTTPException(403, "Your roles do not allow this")
        return admin

    return dependency

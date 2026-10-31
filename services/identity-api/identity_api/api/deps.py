from collections.abc import Awaitable, Callable
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.core.client_ip import Network, client_ip
from identity_api.core.errors import ApiError
from identity_api.db.models import Admin
from identity_api.db.session import get_session
from identity_api.services.auth import SELF_AUDIENCE, AuthService
from identity_api.services.rate_limit import RateLimitGuard
from identity_api.services.tokens import InvalidTokenError, TokenVerifier

_bearer = HTTPBearer(auto_error=False)

UNAUTHORIZED = ApiError(
    401, "unauthorized", "Missing or invalid access token", headers={"WWW-Authenticate": "Bearer"}
)
PASSWORD_CHANGE_REQUIRED = ApiError(
    403, "password_change_required", "Change your password before using the API"
)


def get_auth_service(request: Request) -> AuthService:
    return cast(AuthService, request.app.state.auth)


def get_rate_limits(request: Request) -> RateLimitGuard:
    return cast(RateLimitGuard, request.app.state.rate_limits)


def get_client_ip(request: Request) -> str:
    return client_ip(request, cast(list[Network], request.app.state.trusted_proxies))


def _admin_dependency(*, allow_password_change: bool) -> Callable[..., Awaitable[Admin]]:
    async def dependency(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
        db: Annotated[AsyncSession, Depends(get_session)],
    ) -> Admin:
        if credentials is None:
            raise UNAUTHORIZED
        verifier = cast(TokenVerifier, request.app.state.token_verifier)
        try:
            claims = verifier.verify(credentials.credentials, SELF_AUDIENCE)
        except InvalidTokenError as error:
            raise UNAUTHORIZED from error
        admin = await db.get(Admin, claims.subject)
        if admin is None or not admin.is_active:
            raise UNAUTHORIZED
        # Both the token and the database say so: a stale token cannot skip the change.
        if (claims.must_change_password or admin.must_change_password) and not (
            allow_password_change
        ):
            raise PASSWORD_CHANGE_REQUIRED
        return admin

    return dependency


# The admin behind the access token. Blocked until the first password change is done.
current_admin = _admin_dependency(allow_password_change=False)
# Same, but also accepts an admin who still has to change their password (change-password only).
current_admin_pending_password = _admin_dependency(allow_password_change=True)


FORBIDDEN = ApiError(403, "forbidden", "Your roles do not allow this")


def require_role(role: str) -> Callable[..., Awaitable[Admin]]:
    """The signed-in admin, who must hold `role`. Roles come from the database, so a change
    applies at once here even though tokens carry the old roles for up to 15 minutes.

    Local version until packages/py-auth provides the shared one.
    """

    async def dependency(admin: Annotated[Admin, Depends(current_admin)]) -> Admin:
        if role not in {r.name for r in admin.roles}:
            raise FORBIDDEN
        return admin

    return dependency

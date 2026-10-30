from collections.abc import Awaitable, Callable
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.core.errors import ApiError
from identity_api.db.models import Admin
from identity_api.db.session import get_session
from identity_api.services.auth import SELF_AUDIENCE, AuthService
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

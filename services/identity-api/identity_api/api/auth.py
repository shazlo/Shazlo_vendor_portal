import uuid
from typing import Annotated, cast

from fastapi import APIRouter, Cookie, Depends, Request, Response
from pydantic import BaseModel, Field
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.api.deps import (
    current_admin,
    current_admin_pending_password,
    get_auth_service,
    get_client_ip,
    get_rate_limits,
)
from identity_api.core.errors import ApiError, error_response
from identity_api.core.settings import Settings
from identity_api.db.models import Admin
from identity_api.db.session import get_session
from identity_api.services.auth import (
    INVALID_REFRESH_TOKEN,
    AuthService,
    AuthSession,
)
from identity_api.services.password_policy import MAX_PASSWORD_LENGTH
from identity_api.services.rate_limit import Check, RateLimitGuard

COOKIE_NAME = "refresh_token"
# The browser sends the cookie to the auth endpoints only.
COOKIE_PATH = "/v1/auth"

router = APIRouter(prefix="/auth", tags=["auth"])

Db = Annotated[AsyncSession, Depends(get_session)]
Auth = Annotated[AuthService, Depends(get_auth_service)]
RefreshCookie = Annotated[str | None, Cookie(alias=COOKIE_NAME)]
Limits = Annotated[RateLimitGuard, Depends(get_rate_limits)]
ClientIp = Annotated[str, Depends(get_client_ip)]


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class AdminProfile(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    roles: list[str]
    must_change_password: bool


class SessionResponse(BaseModel):
    """The refresh token is never in the body; it is only ever in the HttpOnly cookie."""

    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - the scheme name, not a secret
    expires_in: int
    must_change_password: bool
    admin: AdminProfile


class TokenRequest(BaseModel):
    audience: str = Field(min_length=1, max_length=64)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - the scheme name, not a secret
    expires_in: int
    audience: str


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def profile_of(admin: Admin) -> AdminProfile:
    return AdminProfile(
        id=admin.id,
        email=admin.email,
        display_name=admin.display_name,
        roles=[role.name for role in admin.roles],
        must_change_password=admin.must_change_password,
    )


def no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def _set_cookie(response: Response, settings: Settings, session: AuthSession) -> None:
    response.set_cookie(
        COOKIE_NAME,
        session.refresh.token,
        expires=session.refresh.expires_at,
        path=COOKIE_PATH,
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _clear_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        COOKIE_NAME,
        path=COOKIE_PATH,
        domain=settings.cookie_domain,
        secure=settings.cookie_secure,
        httponly=True,
        samesite=settings.cookie_samesite,
    )


def _session_response(
    response: Response, settings: Settings, session: AuthSession
) -> SessionResponse:
    no_store(response)
    _set_cookie(response, settings, session)
    return SessionResponse(
        access_token=session.access.token,
        expires_in=settings.access_token_ttl_seconds,
        must_change_password=session.admin.must_change_password,
        admin=profile_of(session.admin),
    )


@router.post("/login")
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Db,
    auth: Auth,
    limits: Limits,
    ip: ClientIp,
) -> SessionResponse:
    settings = _settings(request)
    email = body.email.strip().lower()
    # The email counter is hit before the password is checked, so parallel guesses cannot
    # slip past the limit, and a successful login clears it: in the end it counts failures.
    await limits.check(
        "login",
        [
            Check("ip", ip, settings.rate_limit_login_ip),
            Check("email", email, settings.rate_limit_login_email),
        ],
    )
    session = await auth.login(db, body.email, body.password)
    await limits.reset("login", "email", email)
    return _session_response(response, settings, session)


@router.post("/refresh", response_model=None)
async def refresh(
    request: Request,
    response: Response,
    db: Db,
    auth: Auth,
    limits: Limits,
    ip: ClientIp,
    token: RefreshCookie = None,
) -> SessionResponse | Response:
    settings = _settings(request)
    checks = [Check("ip", ip, settings.rate_limit_refresh_ip)]
    if token:
        try:
            family = await auth.family_of(token)
        except RedisError:
            family = None  # the IP limit still applies; rotating needs Redis anyway
        if family:
            checks.append(Check("session", family, settings.rate_limit_refresh_session))
    # Outside the try below: a rate-limited client keeps its cookie.
    await limits.check("refresh", checks)
    try:
        if not token:
            raise INVALID_REFRESH_TOKEN
        session = await auth.refresh(db, token)
    except ApiError as error:
        # A rejected token is of no further use: have the browser drop it.
        failure = error_response(request, error.status_code, error.code, error.message)
        no_store(failure)
        _clear_cookie(failure, settings)
        return failure
    return _session_response(response, settings, session)


@router.post("/logout", status_code=204)
async def logout(request: Request, auth: Auth, token: RefreshCookie = None) -> Response:
    if token:
        await auth.logout(token)
    response = Response(status_code=204)
    no_store(response)
    _clear_cookie(response, _settings(request))
    return response


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    db: Db,
    auth: Auth,
    limits: Limits,
    admin: Annotated[Admin, Depends(current_admin_pending_password)],
) -> SessionResponse:
    # Counted before the current password is checked, so it limits guesses with a stolen token.
    await limits.check(
        "change_password",
        [Check("admin", str(admin.id), _settings(request).rate_limit_change_password_admin)],
    )
    session = await auth.change_password(db, admin, body.current_password, body.new_password)
    return _session_response(response, _settings(request), session)


@router.post("/token")
async def exchange_token(
    body: TokenRequest,
    request: Request,
    response: Response,
    auth: Auth,
    limits: Limits,
    ip: ClientIp,
    admin: Annotated[Admin, Depends(current_admin)],
) -> TokenResponse:
    """A 15-minute token for one module backend. No refresh token: only the identity session
    refreshes, so several modules never rotate it at the same time."""
    settings = _settings(request)
    await limits.check(
        "token",
        [
            Check("ip", ip, settings.rate_limit_token_ip),
            Check("admin", str(admin.id), settings.rate_limit_token_admin),
        ],
    )
    issued = auth.exchange_token(admin, body.audience)
    no_store(response)
    return TokenResponse(
        access_token=issued.token,
        expires_in=_settings(request).access_token_ttl_seconds,
        audience=body.audience,
    )

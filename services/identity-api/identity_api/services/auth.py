from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.core.errors import ApiError
from identity_api.core.settings import Settings
from identity_api.db.models import Admin
from identity_api.services.password_policy import PasswordPolicyError, check_password
from identity_api.services.passwords import PasswordService
from identity_api.services.refresh_tokens import (
    InvalidRefreshTokenError,
    RefreshSession,
    RefreshTokenStore,
)
from identity_api.services.tokens import IssuedToken, TokenIssuer

# The audience of tokens the shell holds for identity-api itself (ADR 0009).
SELF_AUDIENCE = "identity-api"

INVALID_CREDENTIALS = ApiError(401, "invalid_credentials", "Invalid email or password")
INVALID_REFRESH_TOKEN = ApiError(401, "invalid_refresh_token", "Invalid or expired refresh token")


@dataclass(frozen=True)
class AuthSession:
    admin: Admin
    access: IssuedToken
    refresh: RefreshSession


class AuthService:
    """Login, refresh, logout and change-password. Commits its own database changes."""

    def __init__(
        self,
        settings: Settings,
        passwords: PasswordService,
        issuer: TokenIssuer,
        refresh_tokens: RefreshTokenStore,
    ) -> None:
        self._settings = settings
        self._passwords = passwords
        self._issuer = issuer
        self._refresh_tokens = refresh_tokens

    async def login(self, db: AsyncSession, email: str, password: str) -> AuthSession:
        admin = await db.scalar(select(Admin).where(Admin.email == email.strip().lower()))
        check = await self._passwords.verify_login(admin.password_hash if admin else None, password)
        # An unknown email, a wrong password and a deactivated admin all look the same.
        if admin is None or not check.ok or not admin.is_active:
            raise INVALID_CREDENTIALS
        if check.new_hash:
            admin.password_hash = check.new_hash
        admin.last_login_at = datetime.now(UTC)
        await db.commit()
        return await self._start_session(admin)

    async def refresh(self, db: AsyncSession, token: str) -> AuthSession:
        try:
            rotation = await self._refresh_tokens.rotate(token)
        except InvalidRefreshTokenError as error:
            raise INVALID_REFRESH_TOKEN from error
        admin = await db.get(Admin, rotation.admin_id)
        if admin is None or not admin.is_active:
            await self._refresh_tokens.revoke_family(rotation.session.family_id)
            raise INVALID_REFRESH_TOKEN
        return AuthSession(admin, self._access_token(admin), rotation.session)

    async def logout(self, token: str) -> None:
        await self._refresh_tokens.revoke_by_token(token)

    async def change_password(
        self, db: AsyncSession, admin: Admin, current_password: str, new_password: str
    ) -> AuthSession:
        """Sets a new password, ends every refresh family and starts one new session.

        The access tokens already issued stay valid until they expire (at most 15 minutes).
        """
        check = await self._passwords.verify_login(admin.password_hash, current_password)
        if not check.ok:
            raise ApiError(400, "invalid_current_password", "The current password is wrong")
        try:
            check_password(
                new_password, email=admin.email, min_length=self._settings.password_min_length
            )
        except PasswordPolicyError as error:
            raise ApiError(422, "weak_password", str(error)) from error
        if new_password == current_password:
            raise ApiError(
                422, "weak_password", "The new password must differ from the current one"
            )
        admin.password_hash = await self._passwords.hash(new_password)
        admin.must_change_password = False
        await db.commit()
        await self._refresh_tokens.revoke_all(admin.id)
        return await self._start_session(admin)

    def exchange_token(self, admin: Admin, audience: str) -> IssuedToken:
        """A token for exactly one other service, if one of the admin's roles is allowed there.

        Roles are read from the database, not from the token that asked, so a change of roles
        applies at once to new exchanges.
        """
        allowed = self._settings.audience_roles.get(audience)
        if allowed is None:
            raise ApiError(400, "unknown_audience", "Unknown audience")
        roles = [role.name for role in admin.roles]
        if not set(roles) & set(allowed):
            raise ApiError(403, "audience_not_allowed", "Your roles do not allow this audience")
        return self._issuer.issue(subject=admin.id, roles=roles, audience=audience)

    async def _start_session(self, admin: Admin) -> AuthSession:
        refresh = await self._refresh_tokens.start_family(admin.id)
        return AuthSession(admin, self._access_token(admin), refresh)

    def _access_token(self, admin: Admin) -> IssuedToken:
        return self._issuer.issue(
            subject=admin.id,
            roles=[role.name for role in admin.roles],
            audience=SELF_AUDIENCE,
            must_change_password=admin.must_change_password,
        )

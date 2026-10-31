import uuid
from dataclasses import dataclass

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.core.errors import ApiError
from identity_api.core.settings import Settings
from identity_api.db.models import SUPER_ADMIN, Admin, Role
from identity_api.services.password_policy import PasswordPolicyError, check_password
from identity_api.services.passwords import PasswordService
from identity_api.services.refresh_tokens import RefreshTokenStore

ADMIN_NOT_FOUND = ApiError(404, "admin_not_found", "Admin not found")
EMAIL_TAKEN = ApiError(409, "email_taken", "An admin with this email already exists")
LAST_SUPER_ADMIN = ApiError(
    409, "last_super_admin", "The last active super_admin cannot be deactivated or lose the role"
)
CANNOT_DEACTIVATE_SELF = ApiError(409, "cannot_deactivate_self", "You cannot deactivate yourself")


@dataclass(frozen=True)
class AdminPage:
    items: list[Admin]
    total: int
    limit: int
    offset: int


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class AdminService:
    """Admin management (super_admin only; the routes enforce that). Commits its own changes.

    Role changes reach tokens when the next one is issued (within 15 minutes). Deactivating an
    admin or resetting their password also ends every refresh family, so they cannot renew.
    """

    def __init__(
        self,
        settings: Settings,
        passwords: PasswordService,
        refresh_tokens: RefreshTokenStore,
    ) -> None:
        self._settings = settings
        self._passwords = passwords
        self._refresh_tokens = refresh_tokens

    async def list_roles(self, db: AsyncSession) -> list[Role]:
        return list(await db.scalars(select(Role).order_by(Role.name)))

    async def list_admins(
        self,
        db: AsyncSession,
        *,
        limit: int,
        offset: int,
        query: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
    ) -> AdminPage:
        conditions: list[ColumnElement[bool]] = []
        if query:
            pattern = f"%{_escape_like(query.strip().lower())}%"
            conditions.append(
                Admin.email.like(pattern, escape="\\")
                | func.lower(Admin.display_name).like(pattern, escape="\\")
            )
        if role:
            conditions.append(Admin.roles.any(Role.name == role))
        if is_active is not None:
            conditions.append(Admin.is_active.is_(is_active))
        total = await db.scalar(select(func.count()).select_from(Admin).where(*conditions))
        # The ID breaks ties, so pages never repeat or skip an admin.
        rows = await db.scalars(
            select(Admin)
            .where(*conditions)
            .order_by(Admin.created_at, Admin.id)
            .limit(limit)
            .offset(offset)
        )
        return AdminPage(list(rows), total or 0, limit, offset)

    async def get_admin(self, db: AsyncSession, admin_id: uuid.UUID) -> Admin:
        admin = await db.get(Admin, admin_id)
        if admin is None:
            raise ADMIN_NOT_FOUND
        return admin

    async def create_admin(
        self,
        db: AsyncSession,
        *,
        email: str,
        display_name: str,
        password: str,
        roles: list[str],
    ) -> Admin:
        email = email.strip().lower()
        self._check_password(password, email)
        role_rows = await self._roles(db, roles)
        if await db.scalar(select(Admin.id).where(Admin.email == email)):
            raise EMAIL_TAKEN
        admin = Admin(
            email=email,
            display_name=display_name.strip(),
            password_hash=await self._passwords.hash(password),
            must_change_password=True,
            roles=role_rows,
        )
        db.add(admin)
        try:
            await db.commit()
        except IntegrityError as error:
            # Two requests with the same email can both pass the check above.
            await db.rollback()
            raise EMAIL_TAKEN from error
        return admin

    async def update_admin(
        self,
        db: AsyncSession,
        admin_id: uuid.UUID,
        *,
        actor_id: uuid.UUID,
        display_name: str | None = None,
        roles: list[str] | None = None,
        is_active: bool | None = None,
    ) -> Admin:
        role_rows = await self._roles(db, roles) if roles is not None else None
        # Every change that could remove a super_admin first locks them all, so two requests
        # cannot each leave "one other" and together leave none.
        await self._lock_super_admins(db)
        admin = await self.get_admin(db, admin_id)
        # The lock may have waited for another change: decide on the rows as they are now.
        await db.refresh(admin)
        deactivating = is_active is False and admin.is_active
        if deactivating and admin.id == actor_id:
            raise CANNOT_DEACTIVATE_SELF
        loses_super_admin = role_rows is not None and SUPER_ADMIN not in {
            role.name for role in role_rows
        }
        was_active_super_admin = admin.is_active and _is_super_admin(admin)
        if (
            was_active_super_admin
            and (deactivating or loses_super_admin)
            and await self._active_super_admin_count(db) <= 1
        ):
            raise LAST_SUPER_ADMIN

        if display_name is not None:
            admin.display_name = display_name.strip()
        if role_rows is not None:
            admin.roles = role_rows
        if is_active is not None:
            admin.is_active = is_active
        await db.commit()
        if deactivating:
            await self._refresh_tokens.revoke_all(admin.id)
        return admin

    async def reset_password(
        self, db: AsyncSession, admin_id: uuid.UUID, new_password: str
    ) -> Admin:
        """Sets a temporary password. The admin must change it at the next sign-in."""
        admin = await self.get_admin(db, admin_id)
        self._check_password(new_password, admin.email)
        admin.password_hash = await self._passwords.hash(new_password)
        admin.must_change_password = True
        await db.commit()
        await self._refresh_tokens.revoke_all(admin.id)
        return admin

    def _check_password(self, password: str, email: str) -> None:
        try:
            check_password(password, email=email, min_length=self._settings.password_min_length)
        except PasswordPolicyError as error:
            raise ApiError(422, "weak_password", str(error)) from error

    async def _roles(self, db: AsyncSession, names: list[str]) -> list[Role]:
        unique = sorted(set(names))
        rows = list(await db.scalars(select(Role).where(Role.name.in_(unique))))
        unknown = set(unique) - {role.name for role in rows}
        if unknown:
            raise ApiError(422, "unknown_role", f"Unknown role: {', '.join(sorted(unknown))}")
        return rows

    async def _lock_super_admins(self, db: AsyncSession) -> None:
        await db.execute(
            select(Admin.id)
            .where(Admin.roles.any(Role.name == SUPER_ADMIN))
            .order_by(Admin.id)
            .with_for_update()
        )

    async def _active_super_admin_count(self, db: AsyncSession) -> int:
        count = await db.scalar(
            select(func.count())
            .select_from(Admin)
            .where(Admin.is_active.is_(True), Admin.roles.any(Role.name == SUPER_ADMIN))
        )
        return count or 0


def _is_super_admin(admin: Admin) -> bool:
    return any(role.name == SUPER_ADMIN for role in admin.roles)

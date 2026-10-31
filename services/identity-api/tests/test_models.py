import uuid
from typing import Annotated

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.app import create_app
from identity_api.core.settings import Settings
from identity_api.db.models import SUPER_ADMIN, VENDOR_REVIEWER, Admin, Role, admin_roles
from identity_api.db.session import get_session


def make_admin(email: str = "alice@example.com") -> Admin:
    hash_ = "not-a-real-hash"  # noqa: S105  (placeholder; hashing arrives with #48)
    return Admin(email=email, password_hash=hash_, display_name="Alice")


async def test_roles_are_seeded(session: AsyncSession) -> None:
    names = set((await session.scalars(select(Role.name))).all())
    assert {SUPER_ADMIN, VENDOR_REVIEWER} <= names


async def test_admin_defaults(session: AsyncSession) -> None:
    admin = make_admin()
    session.add(admin)
    await session.flush()
    await session.refresh(admin)

    assert isinstance(admin.id, uuid.UUID)
    assert admin.is_active is True
    assert admin.must_change_password is True
    assert admin.created_at is not None
    assert admin.updated_at is not None
    assert admin.last_login_at is None


async def test_email_is_stored_lower_cased(session: AsyncSession) -> None:
    session.add(make_admin("  Alice@Example.COM "))
    await session.flush()
    assert await session.scalar(select(Admin.email)) == "alice@example.com"


async def test_email_uniqueness_is_case_insensitive(session: AsyncSession) -> None:
    session.add(make_admin("alice@example.com"))
    await session.flush()
    session.add(make_admin("ALICE@example.com"))
    with pytest.raises(IntegrityError, match="uq_admins_email"):
        await session.flush()


@pytest.mark.parametrize("email", ["Bob@example.com", "BOB@EXAMPLE.COM"])
async def test_db_rejects_mixed_case_email_written_directly(
    session: AsyncSession, email: str
) -> None:
    # Bypasses the ORM normalisation: the database itself must refuse it.
    with pytest.raises(IntegrityError, match="ck_admins_email_lower"):
        await session.execute(
            text(
                "INSERT INTO admins (email, password_hash, display_name) "
                "VALUES (:email, 'x', 'Bob')"
            ),
            {"email": email},
        )


async def test_roles_relationship_and_cascade_on_admin_delete(session: AsyncSession) -> None:
    super_admin = await session.get_one(Role, SUPER_ADMIN)
    reviewer = await session.get_one(Role, VENDOR_REVIEWER)
    admin = make_admin()
    admin.roles = [super_admin, reviewer]
    session.add(admin)
    await session.flush()

    links = select(func.count()).select_from(admin_roles).where(admin_roles.c.admin_id == admin.id)
    assert await session.scalar(links) == 2

    await session.delete(admin)
    await session.flush()
    assert await session.scalar(links) == 0


async def test_role_in_use_cannot_be_deleted(session: AsyncSession) -> None:
    admin = make_admin()
    admin.roles = [await session.get_one(Role, VENDOR_REVIEWER)]
    session.add(admin)
    await session.flush()

    with pytest.raises(IntegrityError, match="fk_admin_roles_role_name_roles"):
        await session.execute(text("DELETE FROM roles WHERE name = :n"), {"n": VENDOR_REVIEWER})


def test_get_session_dependency(migrated_db: str, settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"database_url": migrated_db}))

    @app.get("/role-count")
    async def role_count(session: Annotated[AsyncSession, Depends(get_session)]) -> int:
        return await session.scalar(select(func.count()).select_from(Role)) or 0

    with TestClient(app) as client:
        assert client.get("/role-count").json() >= 2


async def test_session_fixture_isolates_tests(session: AsyncSession) -> None:
    # Earlier tests inserted alice@example.com; their transactions were rolled back.
    assert await session.scalar(select(func.count()).select_from(Admin)) == 0

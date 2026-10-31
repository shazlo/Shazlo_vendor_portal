import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api import cli
from identity_api.cli import SeedError, seed_admin
from identity_api.core.settings import Settings
from identity_api.db.models import SUPER_ADMIN, VENDOR_REVIEWER, Admin, Role
from identity_api.services.passwords import PasswordService

EMAIL = "Root@Example.com"
PASSWORD = "correct horse battery"


@pytest.fixture
def passwords(settings: Settings) -> PasswordService:
    cheap = {"argon2_memory_cost_kib": 8, "argon2_time_cost": 1}
    return PasswordService(settings.model_copy(update=cheap))


async def seed(session: AsyncSession, passwords: PasswordService, **overrides: str) -> bool:
    args = {"email": EMAIL, "password": PASSWORD, **overrides}
    return await seed_admin(session, passwords, min_password_length=12, **args)


async def admin_count(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(Admin)) or 0


async def test_seed_creates_roles_and_super_admin(
    session: AsyncSession, passwords: PasswordService
) -> None:
    assert await seed(session, passwords) is True

    admin = await session.scalar(select(Admin).where(Admin.email == "root@example.com"))
    assert admin is not None
    assert [role.name for role in admin.roles] == [SUPER_ADMIN]
    assert admin.must_change_password is True
    assert admin.password_hash.startswith("$argon2id$")
    names = set((await session.scalars(select(Role.name))).all())
    assert {SUPER_ADMIN, VENDOR_REVIEWER} <= names


async def test_seed_twice_changes_nothing(
    session: AsyncSession, passwords: PasswordService
) -> None:
    assert await seed(session, passwords) is True
    first = await session.scalar(select(Admin))
    assert first is not None
    snapshot = (first.id, first.password_hash, first.updated_at)

    assert await seed(session, passwords, password="another long password") is False

    assert await admin_count(session) == 1
    await session.refresh(first)
    assert (first.id, first.password_hash, first.updated_at) == snapshot


async def test_seed_recreates_a_missing_role(
    session: AsyncSession, passwords: PasswordService
) -> None:
    await session.execute(delete(Role).where(Role.name == VENDOR_REVIEWER))
    await seed(session, passwords)
    assert await session.get(Role, VENDOR_REVIEWER) is not None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"password": ""}, "at least"),
        ({"password": "short"}, "at least"),
        ({"password": "root@example.com"}, "email"),
        ({"email": "not-an-email"}, "valid email"),
    ],
)
async def test_seed_refuses_bad_input(
    session: AsyncSession,
    passwords: PasswordService,
    overrides: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(SeedError, match=message):
        await seed(session, passwords, **overrides)
    assert await admin_count(session) == 0


def test_cli_refuses_missing_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], settings: Settings
) -> None:
    monkeypatch.delenv("SEED_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("SEED_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    assert cli.main(["seed"]) == 1
    assert "SEED_ADMIN_PASSWORD" in capsys.readouterr().err


def test_cli_weak_password_is_refused_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], settings: Settings
) -> None:
    monkeypatch.setenv("SEED_ADMIN_EMAIL", "root@example.com")
    monkeypatch.setenv("SEED_ADMIN_PASSWORD", "weakpw")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    assert cli.main(["seed"]) == 1
    output = capsys.readouterr()
    assert "weakpw" not in output.out + output.err

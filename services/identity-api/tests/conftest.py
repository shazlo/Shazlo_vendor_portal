import json
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from identity_api.core.settings import Settings
from identity_api.db.session import async_url
from identity_api.services.keys import generate_private_key, private_key_pem

SERVICE_DIR = Path(__file__).resolve().parents[1]

# Postgres for the database tests (CI sets it; locally use identity_test). Unset: they are skipped.
TEST_DATABASE_URL = os.environ.get("DATABASE_URL", "")


@pytest.fixture(scope="session")
def key_pems() -> dict[str, str]:
    """Two generated private keys by kid. Generating RSA keys is slow, so once per run."""
    return {
        kid: private_key_pem(generate_private_key()).decode()
        for kid in ("test-key-1", "test-key-2")
    }


@pytest.fixture
def settings(key_pems: dict[str, str]) -> Settings:
    return Settings(
        _env_file=None,
        env="test",
        jwt_keys=json.dumps({"test-key-1": key_pems["test-key-1"]}),
        database_url="postgresql+asyncpg://user:pw@localhost:5432/identity_test",
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture
def override() -> Callable[..., Settings]:
    """A validated copy of settings with changes (`model_copy(update=)` skips validation)."""

    def apply(base: Settings, **changes: object) -> Settings:
        return Settings.model_validate({**base.model_dump(), **changes})

    return apply


@pytest.fixture(scope="session")
def alembic_config() -> Config:
    if not TEST_DATABASE_URL:
        pytest.skip("DATABASE_URL is not set")
    # The suite drops and recreates the schema, so never run it against a non-test database.
    database = make_url(TEST_DATABASE_URL).database or ""
    if "test" not in database:
        pytest.fail(f"refusing to migrate {database!r}: DATABASE_URL must name a test database")
    config = Config(str(SERVICE_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", TEST_DATABASE_URL.replace("%", "%%"))
    config.attributes["configure_logger"] = False
    return config


@pytest.fixture(scope="session")
def migrated_db(alembic_config: Config) -> str:
    """Applies the migrations once per test run, starting from an empty schema."""
    command.downgrade(alembic_config, "base")
    command.upgrade(alembic_config, "head")
    return TEST_DATABASE_URL


@pytest.fixture
async def session(migrated_db: str) -> AsyncIterator[AsyncSession]:
    """A session inside a transaction that is rolled back after the test, so tests share no rows.

    Commits inside the test only release a savepoint.
    """
    engine = create_async_engine(async_url(migrated_db), poolclass=NullPool)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        db_session = AsyncSession(
            bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
        )
        try:
            yield db_session
        finally:
            await db_session.close()
            await transaction.rollback()
    await engine.dispose()

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from identity_api.db.session import sync_url

TABLES = {"admins", "roles", "admin_roles"}


def _tables(url: str) -> set[str]:
    engine = create_engine(sync_url(url))
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_downgrade_base_then_upgrade_head(alembic_config: Config, migrated_db: str) -> None:
    assert _tables(migrated_db) >= TABLES

    command.downgrade(alembic_config, "base")
    assert not TABLES & _tables(migrated_db)

    command.upgrade(alembic_config, "head")
    assert _tables(migrated_db) >= TABLES


def test_models_match_migrations(alembic_config: Config, migrated_db: str) -> None:
    # Fails if a model changes without a migration.
    command.check(alembic_config)

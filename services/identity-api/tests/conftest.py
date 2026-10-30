import pytest

from identity_api.core.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        env="test",
        database_url="postgresql+asyncpg://user:pw@localhost:5432/identity_test",
        redis_url="redis://localhost:6379/0",
    )

import pytest
from pydantic import ValidationError

from identity_api.core.settings import Settings


def make(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "database_url": "postgresql://u:p@localhost/db",
        "redis_url": "redis://localhost:6379/0",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def test_missing_required_settings_fail_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None)
    missing = {error["loc"][0] for error in exc.value.errors()}
    assert missing == {"database_url", "redis_url"}


def test_defaults() -> None:
    s = make()
    assert s.env == "dev"
    assert s.cors_allowed_origins == ["http://localhost:5173"]
    assert s.cookie_secure is True
    assert s.cookie_samesite == "strict"
    assert s.access_token_ttl_seconds == 900


def test_cors_origins_are_comma_separated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://a.example, https://b.example ,")
    s = make()
    assert s.cors_allowed_origins == ["https://a.example", "https://b.example"]


def test_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("RATE_LIMIT_HMAC_KEY", "x" * 32)
    s = make()
    assert s.cookie_secure is False
    assert s.env == "prod"


@pytest.mark.parametrize(
    "overrides",
    [{"database_url": "mysql://x"}, {"redis_url": "http://localhost"}, {"env": "staging"}],
)
def test_invalid_values_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        make(**overrides)


def test_rate_limit_defaults() -> None:
    s = make()
    assert (s.rate_limit_login_email.limit, s.rate_limit_login_email.window_seconds) == (5, 900)
    assert s.rate_limit_fail_closed == ["login", "change_password"]
    assert s.trusted_proxies == []


def test_rate_limits_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_LOGIN_IP", "3/10")
    monkeypatch.setenv("RATE_LIMIT_FAIL_CLOSED", "login, refresh,")
    monkeypatch.setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.5/32")
    s = make()
    assert (s.rate_limit_login_ip.limit, s.rate_limit_login_ip.window_seconds) == (3, 10)
    assert s.rate_limit_fail_closed == ["login", "refresh"]
    assert s.trusted_proxies == ["10.0.0.0/8", "192.168.1.5/32"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"rate_limit_login_ip": "5"},
        {"rate_limit_login_ip": "0/60"},
        {"rate_limit_login_ip": "5/0"},
        {"rate_limit_login_ip": "many/60"},
        {"rate_limit_fail_closed": ["logn"]},
        {"trusted_proxies": ["not-a-network"]},
        {"env": "prod"},  # no RATE_LIMIT_HMAC_KEY
    ],
)
def test_invalid_rate_limit_settings_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        make(**overrides)


def test_hmac_key_is_random_outside_prod_and_never_empty() -> None:
    first, second = make(), make()
    assert first.rate_limit_hmac_key is not None and second.rate_limit_hmac_key is not None
    assert (
        first.rate_limit_hmac_key.get_secret_value()
        != second.rate_limit_hmac_key.get_secret_value()
    )

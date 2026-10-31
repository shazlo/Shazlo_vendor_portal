import ipaddress
import secrets
from functools import lru_cache
from typing import Annotated, Literal, Self

from pydantic import BaseModel, BeforeValidator, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

RATE_LIMITED_ENDPOINTS = frozenset({"login", "refresh", "token", "change_password"})


class RateRule(BaseModel, frozen=True):
    """At most `limit` hits per `window_seconds`."""

    limit: int
    window_seconds: int

    @field_validator("limit", "window_seconds")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be at least 1")
        return value


def _parse_rule(value: object) -> object:
    """Accepts `"<limit>/<window seconds>"` (e.g. `5/900`) so environment values stay short."""
    if isinstance(value, str):
        limit, separator, window = value.partition("/")
        if not separator:
            raise ValueError('use "<limit>/<window seconds>", e.g. "5/900"')
        return {"limit": limit.strip(), "window_seconds": window.strip()}
    return value


# NoDecode: the environment value is "5/900", not JSON.
Rule = Annotated[RateRule, BeforeValidator(_parse_rule), NoDecode]


class Settings(BaseSettings):
    """Runtime configuration, read from the environment (and `.env` in local dev).

    Settings that carry credentials have no default, so the app refuses to start without them.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"

    database_url: str
    redis_url: str

    # Origins allowed to call the API with credentials (the Shazlo-One shell).
    # Comma separated in the environment.
    cors_allowed_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]

    # Refresh-token cookie. `Secure` is on by default; turn it off only for local dev.
    cookie_secure: bool = True
    cookie_samesite: Literal["strict", "lax", "none"] = "strict"
    cookie_domain: str | None = None

    jwt_issuer: str = "http://localhost:8001"
    # RS256 keys, from a directory of `<kid>.pem` files and/or a JSON object {"<kid>": "<PEM>"}.
    # `jwt_signing_kid` picks the key that signs; the others are only published in the JWKS.
    jwt_keys_dir: str | None = None
    jwt_keys: SecretStr | None = None
    jwt_signing_kid: str | None = None
    # Which roles may get a token for which service (ADR 0009), as JSON in the environment.
    # An admin gets a token for a service if at least one of their roles is listed for it.
    # Adding a service is a settings change only.
    audience_roles: dict[str, list[str]] = {
        "identity-api": ["super_admin", "vendor_reviewer"],
        "vendor-api": ["super_admin", "vendor_reviewer"],
    }
    access_token_ttl_seconds: int = 15 * 60
    refresh_token_ttl_days: int = 7
    refresh_family_max_days: int = 30

    # Argon2id cost (OWASP baseline: 19 MiB, 2 passes, 1 lane). Raising any of these makes
    # existing hashes rehash on the next successful login.
    argon2_memory_cost_kib: int = 19_456
    argon2_time_cost: int = 2
    argon2_parallelism: int = 1

    password_min_length: int = 12

    # Rate limits (ADR 0009), as "<limit>/<window seconds>". Each endpoint has a limit per
    # client IP and one per subject: the email (hashed) for login, the refresh family for
    # refresh, the admin for token exchange and change-password.
    rate_limit_login_ip: Rule = RateRule(limit=20, window_seconds=60)
    rate_limit_login_email: Rule = RateRule(limit=5, window_seconds=900)
    rate_limit_refresh_ip: Rule = RateRule(limit=60, window_seconds=60)
    rate_limit_refresh_session: Rule = RateRule(limit=20, window_seconds=60)
    rate_limit_token_ip: Rule = RateRule(limit=120, window_seconds=60)
    rate_limit_token_admin: Rule = RateRule(limit=60, window_seconds=60)
    rate_limit_change_password_admin: Rule = RateRule(limit=5, window_seconds=900)
    # What happens when Redis is down. Endpoints listed here answer 503 (fail closed: password
    # guessing must stay limited); the others skip the limit (fail open: availability first).
    rate_limit_fail_closed: Annotated[list[str], NoDecode] = ["login", "change_password"]
    # Keys the hashes that name subjects in Redis, so a Redis dump does not reveal emails.
    # Every instance must share it. Required in prod; elsewhere a random key per process.
    rate_limit_hmac_key: SecretStr | None = None
    # Networks of the reverse proxies whose X-Forwarded-For header is believed (CIDR, comma
    # separated). Empty: the header is ignored and the TCP peer is the client.
    trusted_proxies: Annotated[list[str], NoDecode] = []

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("rate_limit_fail_closed", "trusted_proxies", mode="before")
    @classmethod
    def _split_list(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("rate_limit_fail_closed")
    @classmethod
    def _check_fail_closed(cls, value: list[str]) -> list[str]:
        unknown = set(value) - RATE_LIMITED_ENDPOINTS
        if unknown:
            raise ValueError(
                f"unknown endpoint(s) {sorted(unknown)}; use {sorted(RATE_LIMITED_ENDPOINTS)}"
            )
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _check_trusted_proxies(cls, value: list[str]) -> list[str]:
        for network in value:
            ipaddress.ip_network(network)  # raises ValueError on a bad CIDR
        return value

    @model_validator(mode="after")
    def _rate_limit_key(self) -> Self:
        if self.rate_limit_hmac_key is None:
            if self.env == "prod":
                raise ValueError("RATE_LIMIT_HMAC_KEY is required in prod")
            self.rate_limit_hmac_key = SecretStr(secrets.token_hex(32))
        return self

    @field_validator("audience_roles")
    @classmethod
    def _check_audience_roles(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        if "identity-api" not in value:
            raise ValueError("must include identity-api, the audience of the shell's own token")
        if any(not audience or not roles for audience, roles in value.items()):
            raise ValueError("every audience needs a name and at least one role")
        return value

    @field_validator("database_url")
    @classmethod
    def _check_database_url(cls, value: str) -> str:
        if not value.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError("must start with postgresql:// or postgresql+asyncpg://")
        return value

    @field_validator("redis_url")
    @classmethod
    def _check_redis_url(cls, value: str) -> str:
        if not value.startswith(("redis://", "rediss://")):
            raise ValueError("must start with redis:// or rediss://")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()

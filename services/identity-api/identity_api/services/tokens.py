import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt

from identity_api.core.settings import Settings
from identity_api.services.keys import ALGORITHM, KeyRing

Clock = Callable[[], datetime]


@dataclass(frozen=True)
class IssuedToken:
    token: str
    expires_at: datetime
    jti: str


class TokenIssuer:
    """Signs admin access tokens (ADR 0009): one audience each, ids and roles only."""

    def __init__(
        self, settings: Settings, keyring: KeyRing, clock: Clock = lambda: datetime.now(UTC)
    ) -> None:
        self._issuer = settings.jwt_issuer
        self._ttl_seconds = settings.access_token_ttl_seconds
        self._keyring = keyring
        self._clock = clock

    def issue(
        self,
        *,
        subject: uuid.UUID,
        roles: Sequence[str],
        audience: str,
        must_change_password: bool = False,
    ) -> IssuedToken:
        """`audience` is a single service name; there is deliberately no way to pass several.

        No email or name goes into the token; login and `GET /v1/me` return those.

        A token for an admin who must change their password carries no roles, so no service
        grants it anything, and a `must_change_password` claim that identity-api itself checks.
        """
        if not audience:
            raise ValueError("audience is required")
        issued_at = int(self._clock().timestamp())
        expires_at = issued_at + self._ttl_seconds
        jti = uuid.uuid4().hex
        claims: dict[str, Any] = {
            "iss": self._issuer,
            "sub": str(subject),
            "aud": audience,
            "roles": [] if must_change_password else list(roles),
            "iat": issued_at,
            "exp": expires_at,
            "jti": jti,
        }
        if must_change_password:
            claims["must_change_password"] = True
        signing = self._keyring.signing
        token = jwt.encode(
            claims, signing.private_key, algorithm=ALGORITHM, headers={"kid": signing.kid}
        )
        return IssuedToken(token, datetime.fromtimestamp(expires_at, UTC), jti)


class InvalidTokenError(Exception):
    """The access token is missing a claim, expired, forged or meant for another service."""


@dataclass(frozen=True)
class AccessClaims:
    subject: uuid.UUID
    roles: tuple[str, ...]
    jti: str
    must_change_password: bool


class TokenVerifier:
    """Verifies identity-api's own access tokens the way other services verify them (ADR 0009).

    Only RS256 is accepted; `none`, `HS*` and anything else is rejected before any key is used.
    """

    LEEWAY_SECONDS = 30

    def __init__(self, settings: Settings, keyring: KeyRing) -> None:
        self._issuer = settings.jwt_issuer
        self._keyring = keyring

    def verify(self, token: str, audience: str) -> AccessClaims:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            key = self._keyring.public_keys.get(kid) if isinstance(kid, str) else None
            if key is None:
                raise InvalidTokenError("unknown kid")
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=self._issuer,
                leeway=self.LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "sub", "aud", "jti", "roles"]},
            )
            roles = claims["roles"]
            if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
                raise InvalidTokenError("roles must be a list of strings")
            return AccessClaims(
                subject=uuid.UUID(claims["sub"]),
                roles=tuple(roles),
                jti=claims["jti"],
                must_change_password=claims.get("must_change_password") is True,
            )
        except (jwt.PyJWTError, ValueError, TypeError) as error:
            raise InvalidTokenError(str(error)) from error

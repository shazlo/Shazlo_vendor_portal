import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

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

    def issue(self, *, subject: uuid.UUID, roles: Sequence[str], audience: str) -> IssuedToken:
        """`audience` is a single service name; there is deliberately no way to pass several.

        No email or name goes into the token; login and `GET /v1/me` return those.
        """
        if not audience:
            raise ValueError("audience is required")
        issued_at = int(self._clock().timestamp())
        expires_at = issued_at + self._ttl_seconds
        jti = uuid.uuid4().hex
        claims = {
            "iss": self._issuer,
            "sub": str(subject),
            "aud": audience,
            "roles": list(roles),
            "iat": issued_at,
            "exp": expires_at,
            "jti": jti,
        }
        signing = self._keyring.signing
        token = jwt.encode(
            claims, signing.private_key, algorithm=ALGORITHM, headers={"kid": signing.kid}
        )
        return IssuedToken(token, datetime.fromtimestamp(expires_at, UTC), jti)

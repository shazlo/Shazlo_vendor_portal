import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from shazlo_auth import InvalidTokenError, StaticKeySource, TokenVerifier

from identity_api.core.settings import Settings
from identity_api.services.keys import load_keyring
from identity_api.services.tokens import TokenIssuer

ISSUER = "https://identity.test"
ADMIN = uuid.UUID("11111111-2222-3333-4444-555555555555")


@pytest.fixture
def parts(settings: Settings, key_pems: dict[str, str]) -> tuple[TokenIssuer, TokenVerifier]:
    configured = Settings.model_validate(
        {
            **settings.model_dump(),
            "jwt_issuer": ISSUER,
            "jwt_keys": json.dumps(key_pems),
            "jwt_signing_kid": "test-key-1",
        }
    )
    ring = load_keyring(configured)
    verifier = TokenVerifier(
        StaticKeySource(ring.public_keys), issuer=ISSUER, audience="identity-api"
    )
    return TokenIssuer(configured, ring), verifier


async def test_valid_token_verifies(parts: tuple[TokenIssuer, TokenVerifier]) -> None:
    issuer, verifier = parts
    token = issuer.issue(subject=ADMIN, roles=["vendor_reviewer"], audience="identity-api")
    claims = await verifier.verify(token.token)
    assert claims.subject == ADMIN
    assert claims.roles == ("vendor_reviewer",)
    assert claims.jti == token.jti
    assert claims.must_change_password is False


async def test_pending_password_token_has_no_roles(
    parts: tuple[TokenIssuer, TokenVerifier],
) -> None:
    issuer, verifier = parts
    token = issuer.issue(
        subject=ADMIN, roles=["super_admin"], audience="identity-api", must_change_password=True
    )
    claims = await verifier.verify(token.token)
    assert claims.roles == ()
    assert claims.must_change_password is True


async def test_wrong_audience_is_rejected(parts: tuple[TokenIssuer, TokenVerifier]) -> None:
    issuer, verifier = parts
    token = issuer.issue(subject=ADMIN, roles=[], audience="vendor-api")
    with pytest.raises(InvalidTokenError):
        await verifier.verify(token.token)


async def test_expired_token_is_rejected(
    settings: Settings, key_pems: dict[str, str], parts: tuple[TokenIssuer, TokenVerifier]
) -> None:
    _, verifier = parts
    configured = Settings.model_validate(
        {
            **settings.model_dump(),
            "jwt_issuer": ISSUER,
            "jwt_keys": json.dumps(key_pems),
            "jwt_signing_kid": "test-key-1",
        }
    )
    old = TokenIssuer(
        configured,
        load_keyring(configured),
        clock=lambda: datetime.now(UTC) - timedelta(hours=1),
    ).issue(subject=ADMIN, roles=[], audience="identity-api")
    with pytest.raises(InvalidTokenError):
        await verifier.verify(old.token)


@pytest.mark.parametrize("algorithm", ["HS256", "none"])
async def test_other_algorithms_are_rejected(
    parts: tuple[TokenIssuer, TokenVerifier], algorithm: str
) -> None:
    _, verifier = parts
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": ISSUER, "sub": str(ADMIN), "aud": "identity-api", "roles": ["super_admin"],
        "iat": now, "exp": now + 900, "jti": "x",
    }  # fmt: skip
    forged = jwt.encode(
        claims,
        "secret" * 8 if algorithm == "HS256" else "",
        algorithm=algorithm,
        headers={"kid": "test-key-1"},
    )
    with pytest.raises(InvalidTokenError):
        await verifier.verify(forged)


async def test_unknown_kid_and_garbage_are_rejected(
    parts: tuple[TokenIssuer, TokenVerifier],
) -> None:
    _, verifier = parts
    for token in ["", "garbage", "a.b.c"]:
        with pytest.raises(InvalidTokenError):
            await verifier.verify(token)


async def test_missing_claims_are_rejected(
    parts: tuple[TokenIssuer, TokenVerifier], key_pems: dict[str, str]
) -> None:
    """Correctly signed, but without `jti`, `roles` and `iat`."""
    _, verifier = parts
    exp = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())
    claims = {"iss": ISSUER, "sub": str(ADMIN), "aud": "identity-api", "exp": exp}
    token = jwt.encode(
        claims, key_pems["test-key-1"], algorithm="RS256", headers={"kid": "test-key-1"}
    )
    with pytest.raises(InvalidTokenError):
        await verifier.verify(token)

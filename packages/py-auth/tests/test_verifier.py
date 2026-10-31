import hashlib
import hmac
import json
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shazlo_auth import InvalidTokenError, StaticKeySource, TokenVerifier
from tests.helpers import (
    ADMIN_ID,
    AUDIENCE,
    ISSUER,
    base64url,
    make_claims,
    public_pem,
    raw_token,
)

Sign = Callable[..., str]


@pytest.fixture
def verifier(private_keys: dict[str, rsa.RSAPrivateKey]) -> TokenVerifier:
    keys = {kid: key.public_key() for kid, key in private_keys.items() if kid != "key-3"}
    return TokenVerifier(StaticKeySource(keys), issuer=ISSUER, audience=AUDIENCE)


async def test_a_valid_token_verifies(verifier: TokenVerifier, sign: Sign) -> None:
    token = sign(jti="abc")
    claims = await verifier.verify(token)
    assert claims.subject == ADMIN_ID
    assert claims.roles == ("vendor_reviewer",)
    assert claims.jti == "abc"
    assert claims.must_change_password is False


async def test_the_pending_password_flag_is_read(verifier: TokenVerifier, sign: Sign) -> None:
    claims = await verifier.verify(sign(roles=[], must_change_password=True))
    assert claims.must_change_password is True
    assert claims.roles == ()


async def test_any_known_kid_works_for_rotation(verifier: TokenVerifier, sign: Sign) -> None:
    assert (await verifier.verify(sign("key-2", key="key-2"))).subject == ADMIN_ID


# --- The algorithm is pinned -------------------------------------------------------------


async def test_hs256_signed_with_the_public_key_is_rejected(
    verifier: TokenVerifier, private_keys: dict[str, rsa.RSAPrivateKey]
) -> None:
    """The classic confusion attack: an HMAC keyed with the published public key."""
    header = {"alg": "HS256", "typ": "JWT", "kid": "key-1"}
    claims = make_claims(roles=["super_admin"])
    signing_input = (
        f"{base64url(json.dumps(header).encode())}.{base64url(json.dumps(claims).encode())}"
    )
    for secret in (public_pem(private_keys["key-1"]), b"secret" * 8):
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        forged = f"{signing_input}.{base64url(signature)}"
        with pytest.raises(InvalidTokenError):
            await verifier.verify(forged)


@pytest.mark.parametrize(
    "algorithm", ["none", "None", "HS256", "HS384", "HS512", "RS384", "ES256", "PS256"]
)
async def test_other_algorithms_are_rejected(verifier: TokenVerifier, algorithm: str) -> None:
    forged = raw_token({"alg": algorithm, "typ": "JWT", "kid": "key-1"}, make_claims(), b"x")
    with pytest.raises(InvalidTokenError, match="only RS256"):
        await verifier.verify(forged)


async def test_rs384_signed_with_the_right_key_is_rejected(
    verifier: TokenVerifier, private_keys: dict[str, rsa.RSAPrivateKey]
) -> None:
    token = jwt.encode(
        make_claims(), private_keys["key-1"], algorithm="RS384", headers={"kid": "key-1"}
    )
    with pytest.raises(InvalidTokenError):
        await verifier.verify(token)


async def test_an_unsigned_token_is_rejected(verifier: TokenVerifier) -> None:
    unsigned = jwt.encode(make_claims(), "", algorithm="none", headers={"kid": "key-1"})
    with pytest.raises(InvalidTokenError):
        await verifier.verify(unsigned)


# --- Audience, issuer, expiry ------------------------------------------------------------


async def test_a_token_for_another_audience_is_rejected(
    verifier: TokenVerifier, sign: Sign
) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(aud="billing-api"))


async def test_a_token_that_lists_several_audiences_is_rejected(
    verifier: TokenVerifier, sign: Sign
) -> None:
    with pytest.raises(InvalidTokenError, match="single"):
        await verifier.verify(sign(aud=[AUDIENCE, "billing-api"]))


async def test_a_token_without_audience_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(aud=None))


async def test_a_token_from_another_issuer_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(iss="https://vendor-api.test"))


async def test_an_expired_token_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    now = int(time.time())
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(iat=now - 1000, exp=now - 100))


async def test_leeway_is_30_seconds(verifier: TokenVerifier, sign: Sign) -> None:
    now = int(time.time())
    assert await verifier.verify(sign(iat=now - 900, exp=now - 10))  # within the leeway
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(iat=now - 900, exp=now - 40))  # beyond it


async def test_a_token_from_the_future_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    now = int(time.time())
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(nbf=now + 600))


# --- Keys ---------------------------------------------------------------------------------


async def test_an_unknown_kid_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    with pytest.raises(InvalidTokenError, match="unknown kid"):
        await verifier.verify(sign("key-3", key="key-3"))


async def test_a_missing_kid_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    with pytest.raises(InvalidTokenError, match="kid"):
        await verifier.verify(sign(None))


async def test_a_signature_from_another_key_is_rejected(
    verifier: TokenVerifier, sign: Sign
) -> None:
    """Right kid in the header, but signed by a key that is not that kid's."""
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign("key-1", key="key-2"))


async def test_a_tampered_payload_is_rejected(verifier: TokenVerifier, sign: Sign) -> None:
    header, _, signature = sign().split(".")
    forged_payload = base64url(json.dumps(make_claims(roles=["super_admin"])).encode())
    with pytest.raises(InvalidTokenError):
        await verifier.verify(f"{header}.{forged_payload}.{signature}")


# --- Required claims ---------------------------------------------------------------------


@pytest.mark.parametrize("claim", ["sub", "roles", "exp", "iat", "iss", "jti"])
async def test_missing_claims_are_rejected(verifier: TokenVerifier, sign: Sign, claim: str) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(**{claim: None}))


@pytest.mark.parametrize(
    "changes",
    [
        {"roles": "super_admin"},
        {"roles": [1, 2]},
        {"roles": {"a": "b"}},
        {"sub": "not-a-uuid"},
        {"sub": 12},
        {"jti": 5},
    ],
)
async def test_badly_typed_claims_are_rejected(
    verifier: TokenVerifier, sign: Sign, changes: dict[str, Any]
) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify(sign(**changes))


@pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "a.b", "....", "é.é.é"])
async def test_garbage_is_rejected(verifier: TokenVerifier, token: str) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify(token)

import base64
import json
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://identity.test"
AUDIENCE = "vendor-api"
ADMIN_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")


def jwk_of(kid: str, key: rsa.RSAPrivateKey, **changes: Any) -> dict[str, Any]:
    jwk = dict(RSAAlgorithm.to_jwk(key.public_key(), as_dict=True))
    return {**jwk, "kid": kid, "use": "sig", "alg": "RS256", **changes}


def public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def raw_token(header: dict[str, Any], claims: dict[str, Any], signature: bytes = b"") -> str:
    """A token assembled by hand, for algorithms PyJWT refuses to produce."""
    parts = [base64url(json.dumps(header).encode()), base64url(json.dumps(claims).encode())]
    return ".".join([*parts, base64url(signature)])


def make_claims(**changes: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": str(ADMIN_ID),
        "aud": AUDIENCE,
        "roles": ["vendor_reviewer"],
        "iat": now,
        "exp": now + 900,
        "jti": uuid.uuid4().hex,
    }
    claims.update(changes)
    return {key: value for key, value in claims.items() if value is not None}

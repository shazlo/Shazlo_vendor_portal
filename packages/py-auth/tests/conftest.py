from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.helpers import make_claims


@pytest.fixture(scope="session")
def private_keys() -> dict[str, rsa.RSAPrivateKey]:
    """Generating RSA keys is slow, so three of them once per run."""
    return {
        kid: rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for kid in ("key-1", "key-2", "key-3")
    }


@pytest.fixture
def sign(private_keys: dict[str, rsa.RSAPrivateKey]) -> Callable[..., str]:
    """Signs claims with RS256. Pass `claim=None` to leave a claim out."""

    def make(kid: str | None = "key-1", *, key: str = "key-1", **changes: Any) -> str:
        headers = {"kid": kid} if kid is not None else {}
        return jwt.encode(
            make_claims(**changes), private_keys[key], algorithm="RS256", headers=headers
        )

    return make

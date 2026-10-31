from collections.abc import Mapping
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import rsa


class KeySource(Protocol):
    """Where a verifier finds the public key for a token's `kid`."""

    async def get_key(self, kid: str) -> rsa.RSAPublicKey | None:
        """The key, or None if there is no such key (the token is then rejected)."""
        ...


class StaticKeySource:
    """A fixed set of keys, for the service that holds them itself (identity-api)."""

    def __init__(self, keys: Mapping[str, rsa.RSAPublicKey]) -> None:
        self._keys = dict(keys)

    async def get_key(self, kid: str) -> rsa.RSAPublicKey | None:
        return self._keys.get(kid)

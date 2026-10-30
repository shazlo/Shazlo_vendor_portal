import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from identity_api.core.settings import Settings

KID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
KEY_BITS = 2048
ALGORITHM = "RS256"


class KeyConfigError(Exception):
    """The signing keys are missing or invalid. The message is safe to print."""


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey


class KeyRing:
    """The published public keys, and the one private key that signs new tokens.

    Rotation is a configuration change: a key that is in the ring but not the signing key is
    published only, which is how a new key is announced before use and an old key is kept until
    its tokens have expired.
    """

    def __init__(self, public_keys: Mapping[str, rsa.RSAPublicKey], signing: SigningKey) -> None:
        if signing.kid not in public_keys:
            raise KeyConfigError(f"signing key {signing.kid!r} is not in the key ring")
        self.signing = signing
        self.kids = tuple(public_keys)
        # Built from public keys only, so private parameters cannot reach the document.
        self._jwks: dict[str, Any] = {
            "keys": [
                {**_public_jwk(key), "kid": kid, "use": "sig", "alg": ALGORITHM}
                for kid, key in public_keys.items()
            ]
        }

    def jwks(self) -> dict[str, Any]:
        return self._jwks


def _public_jwk(key: rsa.RSAPublicKey) -> dict[str, Any]:
    return dict(RSAAlgorithm.to_jwk(key, as_dict=True))


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)


def private_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_pem(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def new_kid(now: datetime | None = None) -> str:
    """A readable, unique key ID such as `2026-10-30-a1b2c3`."""
    return f"{(now or datetime.now(UTC)):%Y-%m-%d}-{secrets.token_hex(3)}"


def write_new_key(directory: Path, kid: str) -> Path:
    """Writes a fresh private key to `<directory>/<kid>.pem`, readable by the owner only.

    Never overwrites: an existing file with the same name raises `FileExistsError`.
    """
    if not KID_PATTERN.match(kid):
        raise KeyConfigError("kid may only contain letters, digits, '.', '_' and '-' (max 64)")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{kid}.pem"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(private_key_pem(generate_private_key()))
    return path


def _parse_pem(kid: str, pem: bytes) -> rsa.RSAPrivateKey | rsa.RSAPublicKey:
    key: object
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        try:
            key = serialization.load_pem_public_key(pem)
        except (ValueError, UnsupportedAlgorithm) as error:
            raise KeyConfigError(f"key {kid!r} is not a valid unencrypted PEM key") from error
    if not isinstance(key, rsa.RSAPrivateKey | rsa.RSAPublicKey):
        raise KeyConfigError(f"key {kid!r} is not an RSA key")
    if key.key_size < KEY_BITS:
        raise KeyConfigError(f"key {kid!r} is shorter than {KEY_BITS} bits")
    return key


def _collect_pems(settings: Settings) -> dict[str, bytes]:
    pems: dict[str, bytes] = {}

    def add(kid: str, pem: bytes, source: str) -> None:
        if not KID_PATTERN.match(kid):
            raise KeyConfigError(f"invalid kid {kid!r} in {source}")
        if kid in pems:
            raise KeyConfigError(f"kid {kid!r} is configured twice")
        pems[kid] = pem

    if settings.jwt_keys_dir:
        directory = Path(settings.jwt_keys_dir)
        if not directory.is_dir():
            raise KeyConfigError("JWT_KEYS_DIR is not a directory")
        for path in sorted(directory.glob("*.pem")):
            add(path.stem, path.read_bytes(), "JWT_KEYS_DIR")

    if settings.jwt_keys:
        try:
            from_env = json.loads(settings.jwt_keys.get_secret_value())
        except ValueError as error:
            raise KeyConfigError("JWT_KEYS is not valid JSON") from error
        if not isinstance(from_env, dict) or not all(
            isinstance(value, str) for value in from_env.values()
        ):
            raise KeyConfigError('JWT_KEYS must be a JSON object of {"<kid>": "<PEM>"}')
        for kid, pem in from_env.items():
            add(kid, pem.encode(), "JWT_KEYS")
    return pems


def load_keyring(settings: Settings) -> KeyRing:
    """Builds the key ring from `JWT_KEYS_DIR` (`<kid>.pem` files) and/or `JWT_KEYS` (JSON).

    A key may be a private PEM or, for a key that is only published (a retired key kept until
    its tokens expire), a public PEM. The signing key must be private.
    """
    pems = _collect_pems(settings)
    if not pems:
        raise KeyConfigError(
            "no JWT keys configured: set JWT_KEYS_DIR or JWT_KEYS "
            "(create one with `python -m identity_api.cli generate-key`)"
        )
    keys = {kid: _parse_pem(kid, pem) for kid, pem in pems.items()}

    signing_kid = settings.jwt_signing_kid or None  # an empty variable counts as unset
    if signing_kid is None:
        if len(keys) != 1:
            raise KeyConfigError("several keys are configured: set JWT_SIGNING_KID")
        signing_kid = next(iter(keys))
    signing_key = keys.get(signing_kid)
    if signing_key is None:
        raise KeyConfigError(f"JWT_SIGNING_KID {signing_kid!r} is not one of the configured keys")
    if not isinstance(signing_key, rsa.RSAPrivateKey):
        raise KeyConfigError(f"signing key {signing_kid!r} has no private part")

    public_keys = {
        kid: key if isinstance(key, rsa.RSAPublicKey) else key.public_key()
        for kid, key in keys.items()
    }
    return KeyRing(public_keys, SigningKey(signing_kid, signing_key))

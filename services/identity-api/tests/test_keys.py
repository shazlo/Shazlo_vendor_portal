import json
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from identity_api import cli
from identity_api.core.settings import Settings
from identity_api.services.keys import (
    KeyConfigError,
    generate_private_key,
    load_keyring,
    private_key_pem,
    public_key_pem,
    write_new_key,
)

Override = Callable[..., Settings]


def public_pem(private_pem: str) -> str:
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return public_key_pem(key.public_key()).decode()


def test_loads_a_single_key_without_a_signing_kid(settings: Settings) -> None:
    ring = load_keyring(settings)
    assert ring.signing.kid == "test-key-1"
    assert ring.kids == ("test-key-1",)


def test_empty_signing_kid_counts_as_unset(settings: Settings, override: Override) -> None:
    ring = load_keyring(override(settings, jwt_signing_kid=""))
    assert ring.signing.kid == "test-key-1"


def test_several_keys_need_an_explicit_signing_kid(
    settings: Settings, override: Override, key_pems: dict[str, str]
) -> None:
    both = override(settings, jwt_keys=json.dumps(key_pems))
    with pytest.raises(KeyConfigError, match="JWT_SIGNING_KID"):
        load_keyring(both)
    ring = load_keyring(override(both, jwt_signing_kid="test-key-2"))
    assert ring.signing.kid == "test-key-2"
    assert set(ring.kids) == {"test-key-1", "test-key-2"}


def test_a_public_only_key_is_published_but_cannot_sign(
    settings: Settings, override: Override, key_pems: dict[str, str]
) -> None:
    keys = {"test-key-1": key_pems["test-key-1"], "old": public_pem(key_pems["test-key-2"])}
    base = override(settings, jwt_keys=json.dumps(keys))
    ring = load_keyring(override(base, jwt_signing_kid="test-key-1"))
    assert set(ring.kids) == {"test-key-1", "old"}
    with pytest.raises(KeyConfigError, match="no private part"):
        load_keyring(override(base, jwt_signing_kid="old"))


def test_unknown_signing_kid_is_rejected(settings: Settings, override: Override) -> None:
    with pytest.raises(KeyConfigError, match="not one of the configured keys"):
        load_keyring(override(settings, jwt_signing_kid="nope"))


def test_no_keys_fails_with_a_pointer_to_the_command(
    settings: Settings, override: Override
) -> None:
    with pytest.raises(KeyConfigError, match="generate-key"):
        load_keyring(override(settings, jwt_keys=None))


@pytest.mark.parametrize("keys", [{"k": "not a pem"}, {"bad kid!": "x"}], ids=["pem", "kid"])
def test_invalid_keys_are_rejected(
    settings: Settings, override: Override, keys: dict[str, str]
) -> None:
    with pytest.raises(KeyConfigError):
        load_keyring(override(settings, jwt_keys=json.dumps(keys)))


def test_malformed_json_is_rejected_without_echoing_it(
    settings: Settings, override: Override
) -> None:
    with pytest.raises(KeyConfigError, match="not valid JSON") as error:
        load_keyring(override(settings, jwt_keys="{secret-looking"))
    assert "secret-looking" not in str(error.value)


def test_short_keys_are_rejected(settings: Settings, override: Override) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    keys = json.dumps({"weak": private_key_pem(weak).decode()})
    with pytest.raises(KeyConfigError, match="shorter than 2048"):
        load_keyring(override(settings, jwt_keys=keys))


def test_loads_keys_from_a_directory_and_rejects_duplicates(
    settings: Settings, override: Override, key_pems: dict[str, str], tmp_path: Path
) -> None:
    (tmp_path / "test-key-2.pem").write_text(key_pems["test-key-2"])
    from_dir = override(settings, jwt_keys=None, jwt_keys_dir=str(tmp_path))
    assert load_keyring(from_dir).kids == ("test-key-2",)

    duplicate = override(from_dir, jwt_keys=json.dumps({"test-key-2": key_pems["test-key-2"]}))
    with pytest.raises(KeyConfigError, match="configured twice"):
        load_keyring(duplicate)


def test_missing_directory_is_rejected(
    settings: Settings, override: Override, tmp_path: Path
) -> None:
    with pytest.raises(KeyConfigError, match="not a directory"):
        load_keyring(override(settings, jwt_keys_dir=str(tmp_path / "absent")))


def test_write_new_key_is_private_and_never_overwrites(tmp_path: Path) -> None:
    path = write_new_key(tmp_path, "dev-1")
    assert path.name == "dev-1.pem"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    with pytest.raises(FileExistsError):
        write_new_key(tmp_path, "dev-1")


def test_write_new_key_rejects_path_tricks(tmp_path: Path) -> None:
    with pytest.raises(KeyConfigError):
        write_new_key(tmp_path, "../escape")


def test_generate_key_command_writes_a_loadable_key(
    settings: Settings,
    override: Override,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["generate-key", "--dir", str(tmp_path), "--kid", "dev-1"]) == 0
    output = capsys.readouterr().out
    assert "dev-1" in output
    assert "PRIVATE KEY" not in output
    ring = load_keyring(override(settings, jwt_keys=None, jwt_keys_dir=str(tmp_path)))
    assert ring.signing.kid == "dev-1"
    # Running it again with the same kid fails instead of replacing the key.
    assert cli.main(["generate-key", "--dir", str(tmp_path), "--kid", "dev-1"]) == 1


def test_generated_keys_are_2048_bit_rsa() -> None:
    assert generate_private_key().key_size == 2048

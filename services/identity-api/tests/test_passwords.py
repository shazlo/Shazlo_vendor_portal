from identity_api.core.settings import Settings
from identity_api.services.passwords import PasswordService

PASSWORD = "correct horse battery"


def make_service(settings: Settings, **overrides: int) -> PasswordService:
    # Small costs keep the tests fast.
    cheap = {"argon2_memory_cost_kib": 8, "argon2_time_cost": 1, "argon2_parallelism": 1}
    return PasswordService(settings.model_copy(update={**cheap, **overrides}))


async def test_hash_is_argon2id_and_not_the_password(settings: Settings) -> None:
    hashed = await make_service(settings).hash(PASSWORD)
    assert hashed.startswith("$argon2id$")
    assert PASSWORD not in hashed


async def test_hash_is_salted(settings: Settings) -> None:
    service = make_service(settings)
    assert await service.hash(PASSWORD) != await service.hash(PASSWORD)


async def test_correct_password_verifies(settings: Settings) -> None:
    service = make_service(settings)
    result = await service.verify_login(await service.hash(PASSWORD), PASSWORD)
    assert result.ok
    assert result.new_hash is None


async def test_wrong_password_fails(settings: Settings) -> None:
    service = make_service(settings)
    assert not (await service.verify_login(await service.hash(PASSWORD), "wrong")).ok


async def test_unknown_email_looks_like_wrong_password(settings: Settings) -> None:
    service = make_service(settings)
    unknown = await service.verify_login(None, PASSWORD)
    wrong = await service.verify_login(await service.hash(PASSWORD), "wrong")
    assert unknown == wrong


async def test_unknown_email_still_runs_a_verification(settings: Settings) -> None:
    service = make_service(settings)
    calls: list[str] = []
    original = service._verify  # noqa: SLF001

    def spy(password_hash: str, password: str) -> bool:
        calls.append(password_hash)
        return original(password_hash, password)

    service._verify = spy  # type: ignore[method-assign]  # noqa: SLF001
    await service.verify_login(None, PASSWORD)
    assert calls == [service._dummy_hash]  # noqa: SLF001


async def test_garbage_stored_hash_is_a_failed_login(settings: Settings) -> None:
    assert not (await make_service(settings).verify_login("not-a-hash", PASSWORD)).ok


async def test_rehash_when_parameters_change(settings: Settings) -> None:
    old = await make_service(settings, argon2_time_cost=1).hash(PASSWORD)
    stronger = make_service(settings, argon2_time_cost=2)

    result = await stronger.verify_login(old, PASSWORD)

    assert result.ok
    assert result.new_hash is not None
    # The new hash verifies and needs no further rehash.
    again = await stronger.verify_login(result.new_hash, PASSWORD)
    assert again.ok
    assert again.new_hash is None


async def test_no_rehash_on_wrong_password(settings: Settings) -> None:
    old = await make_service(settings, argon2_time_cost=1).hash(PASSWORD)
    result = await make_service(settings, argon2_time_cost=2).verify_login(old, "wrong")
    assert not result.ok
    assert result.new_hash is None

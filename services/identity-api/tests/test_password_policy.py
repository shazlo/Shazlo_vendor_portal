import pytest

from identity_api.services.password_policy import (
    MAX_PASSWORD_LENGTH,
    PasswordPolicyError,
    check_password,
)

EMAIL = "alice@example.com"


def test_accepts_a_long_enough_password() -> None:
    check_password("correct horse battery", email=EMAIL, min_length=12)


def test_rejects_short_password() -> None:
    with pytest.raises(PasswordPolicyError, match="at least 12"):
        check_password("short", email=EMAIL, min_length=12)


def test_rejects_overlong_password() -> None:
    with pytest.raises(PasswordPolicyError, match="at most"):
        check_password("x" * (MAX_PASSWORD_LENGTH + 1), email=EMAIL, min_length=12)


@pytest.mark.parametrize("password", [EMAIL, EMAIL.upper(), f"  {EMAIL} "])
def test_rejects_password_equal_to_email(password: str) -> None:
    with pytest.raises(PasswordPolicyError, match="email"):
        check_password(password, email=EMAIL, min_length=12)


def test_error_never_contains_the_password() -> None:
    password = "hunter2-but-too-short"
    with pytest.raises(PasswordPolicyError) as info:
        check_password(password, email=EMAIL, min_length=40)
    assert password not in str(info.value)

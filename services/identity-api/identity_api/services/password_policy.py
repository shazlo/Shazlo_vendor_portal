class PasswordPolicyError(ValueError):
    """The password breaks the policy. The message never contains the password."""


# Argon2 accepts long inputs, but hashing megabytes per request is a cheap way to burn CPU.
MAX_PASSWORD_LENGTH = 128


def check_password(password: str, *, email: str, min_length: int) -> None:
    """Raises PasswordPolicyError if the password is not acceptable.

    Shared by admin creation, change-password and the seed CLI.
    """
    if len(password) < min_length:
        raise PasswordPolicyError(f"Password must be at least {min_length} characters long")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters long")
    if password.strip().lower() == email.strip().lower():
        raise PasswordPolicyError("Password must not be the same as the email address")

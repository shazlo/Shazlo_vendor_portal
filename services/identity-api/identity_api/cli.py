"""Operator commands: `python -m identity_api.cli seed` and `generate-key`."""

import argparse
import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.core.settings import Settings, get_settings
from identity_api.db.models import SUPER_ADMIN, VENDOR_REVIEWER, Admin, Role
from identity_api.db.session import create_engine, create_sessionmaker
from identity_api.services.keys import KeyConfigError, new_kid, write_new_key
from identity_api.services.password_policy import PasswordPolicyError, check_password
from identity_api.services.passwords import PasswordService

logger = logging.getLogger("identity_api.cli")

DEFAULT_ROLES = {
    SUPER_ADMIN: "Manages admin users and roles",
    VENDOR_REVIEWER: "Reviews vendor applications",
}


class SeedError(Exception):
    """The seed cannot run. The message is safe to print."""


async def seed_admin(
    session: AsyncSession,
    passwords: PasswordService,
    *,
    email: str,
    password: str,
    min_password_length: int,
    display_name: str = "Super Admin",
) -> bool:
    """Creates the roles and the first super_admin. Returns False if the admin already exists.

    Safe to run repeatedly: existing roles and an existing admin are left untouched, so a
    changed SEED_ADMIN_PASSWORD never overwrites a password someone has since set.
    """
    email = email.strip().lower()
    if "@" not in email:
        raise SeedError("SEED_ADMIN_EMAIL is not a valid email address")
    try:
        check_password(password, email=email, min_length=min_password_length)
    except PasswordPolicyError as error:
        raise SeedError(str(error)) from error

    await session.execute(
        insert(Role)
        .values([{"name": name, "description": text} for name, text in DEFAULT_ROLES.items()])
        .on_conflict_do_nothing(index_elements=[Role.name])
    )

    if await session.scalar(select(Admin.id).where(Admin.email == email)) is not None:
        await session.commit()
        return False

    super_admin_role = await session.get(Role, SUPER_ADMIN)
    if super_admin_role is None:
        raise SeedError("the super_admin role could not be created")
    admin = Admin(
        email=email,
        password_hash=await passwords.hash(password),
        display_name=display_name,
        must_change_password=True,
        roles=[super_admin_role],
    )
    session.add(admin)
    await session.commit()
    return True


def _read_credentials() -> tuple[str, str]:
    email = os.environ.get("SEED_ADMIN_EMAIL", "").strip()
    password = os.environ.get("SEED_ADMIN_PASSWORD", "")
    if not email or not password:
        if not sys.stdin.isatty():
            raise SeedError("Set SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD, or run in a terminal")
        email = email or input("Admin email: ").strip()
        password = password or getpass.getpass("Admin password: ")
    return email, password


async def _run_seed(settings: Settings) -> None:
    email, password = _read_credentials()
    display_name = os.environ.get("SEED_ADMIN_NAME", "").strip() or "Super Admin"
    engine = create_engine(settings.database_url)
    try:
        async with create_sessionmaker(engine)() as session:
            created = await seed_admin(
                session,
                PasswordService(settings),
                email=email,
                password=password,
                min_password_length=settings.password_min_length,
                display_name=display_name,
            )
    finally:
        await engine.dispose()
    # The email is not a secret; the password and its hash are never printed.
    if created:
        print(f"Created super_admin {email.lower()} (must change password on first login)")
    else:
        print(f"Admin {email.lower()} already exists; nothing changed")


def _generate_key(directory: Path, kid: str | None) -> None:
    kid = kid or new_kid()
    try:
        path = write_new_key(directory, kid)
    except FileExistsError as error:
        raise SeedError(f"{directory / (kid + '.pem')} already exists") from error
    except KeyConfigError as error:
        raise SeedError(str(error)) from error
    # Only the file name is printed, never the key.
    print(f"Wrote private key {path}")
    print(f"Set JWT_KEYS_DIR={directory} and JWT_SIGNING_KID={kid} to sign with it.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity_api.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("seed", help="create the default roles and the first super_admin")
    keygen = commands.add_parser("generate-key", help="create an RS256 signing key for local dev")
    keygen.add_argument("--dir", type=Path, default=Path(".keys"), help="default: ./.keys")
    keygen.add_argument("--kid", help="key ID; default is the date plus a random suffix")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-key":
            _generate_key(args.dir, args.kid)
        else:
            asyncio.run(_run_seed(get_settings()))
    except SeedError as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

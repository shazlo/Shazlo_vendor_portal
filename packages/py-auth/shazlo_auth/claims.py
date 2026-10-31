import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class AccessClaims:
    subject: uuid.UUID
    roles: tuple[str, ...]
    jti: str
    must_change_password: bool = False

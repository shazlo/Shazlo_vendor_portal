import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    String,
    Table,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from identity_api.db.base import Base

SUPER_ADMIN = "super_admin"
VENDOR_REVIEWER = "vendor_reviewer"

admin_roles = Table(
    "admin_roles",
    Base.metadata,
    Column(
        "admin_id",
        UUID(as_uuid=True),
        ForeignKey("admins.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "role_name",
        String(64),
        ForeignKey("roles.name", ondelete="RESTRICT", onupdate="CASCADE"),
        primary_key=True,
    ),
)


class Role(Base):
    __tablename__ = "roles"

    # Plain strings such as `super_admin`; new services add `<area>_<role>` names (ADR 0009).
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, server_default="")


class Admin(Base):
    __tablename__ = "admins"
    __table_args__ = (
        # Stored lower-cased, so the unique constraint is case-insensitive at the DB level.
        CheckConstraint("email = lower(email)", name="email_lower"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    must_change_password: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    roles: Mapped[list[Role]] = relationship(secondary=admin_roles, lazy="selectin")

    @validates("email")
    def _normalise_email(self, _key: str, value: str) -> str:
        return value.strip().lower()

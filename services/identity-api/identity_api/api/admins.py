import uuid
from datetime import datetime
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from identity_api.api.auth import no_store
from identity_api.api.deps import require_role
from identity_api.db.models import SUPER_ADMIN, Admin, Role
from identity_api.db.session import get_session
from identity_api.services.admins import AdminService
from identity_api.services.password_policy import MAX_PASSWORD_LENGTH

# Every endpoint here is for super_admin only (ADR 0009). One dependency object, so FastAPI
# runs the check once per request even where an endpoint also asks for the acting admin.
super_admin = require_role(SUPER_ADMIN)
router = APIRouter(tags=["admins"], dependencies=[Depends(super_admin)])

Db = Annotated[AsyncSession, Depends(get_session)]

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


def get_admin_service(request: Request) -> AdminService:
    return cast(AdminService, request.app.state.admins)


Service = Annotated[AdminService, Depends(get_admin_service)]
Actor = Annotated[Admin, Depends(super_admin)]


class AdminOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    roles: list[str]
    is_active: bool
    must_change_password: bool
    created_at: datetime
    last_login_at: datetime | None


class AdminList(BaseModel):
    items: list[AdminOut]
    total: int
    limit: int
    offset: int


class RoleOut(BaseModel):
    name: str
    description: str


class CreateAdminRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=EMAIL_PATTERN)
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    roles: list[str] = Field(min_length=1, max_length=20)


class UpdateAdminRequest(BaseModel):
    """Only the fields that are sent change."""

    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    roles: list[str] | None = Field(default=None, min_length=1, max_length=20)
    is_active: bool | None = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


def admin_out(admin: Admin) -> AdminOut:
    return AdminOut(
        id=admin.id,
        email=admin.email,
        display_name=admin.display_name,
        roles=sorted(role.name for role in admin.roles),
        is_active=admin.is_active,
        must_change_password=admin.must_change_password,
        created_at=admin.created_at,
        last_login_at=admin.last_login_at,
    )


def role_out(role: Role) -> RoleOut:
    return RoleOut(name=role.name, description=role.description)


@router.get("/roles")
async def list_roles(response: Response, db: Db, service: Service) -> list[RoleOut]:
    no_store(response)
    return [role_out(role) for role in await service.list_roles(db)]


@router.get("/admins")
async def list_admins(
    response: Response,
    db: Db,
    service: Service,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    q: Annotated[str | None, Query(max_length=200, description="Email or name contains")] = None,
    role: Annotated[str | None, Query(max_length=64)] = None,
    is_active: bool | None = None,
) -> AdminList:
    no_store(response)
    page = await service.list_admins(
        db, limit=limit, offset=offset, query=q, role=role, is_active=is_active
    )
    return AdminList(
        items=[admin_out(admin) for admin in page.items],
        total=page.total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/admins", status_code=201)
async def create_admin(
    body: CreateAdminRequest, response: Response, db: Db, service: Service
) -> AdminOut:
    """The new admin must change the initial password at the first sign-in."""
    no_store(response)
    admin = await service.create_admin(
        db,
        email=body.email,
        display_name=body.display_name,
        password=body.password,
        roles=body.roles,
    )
    response.headers["Location"] = f"/v1/admins/{admin.id}"
    return admin_out(admin)


@router.get("/admins/{admin_id}")
async def get_admin(admin_id: uuid.UUID, response: Response, db: Db, service: Service) -> AdminOut:
    no_store(response)
    return admin_out(await service.get_admin(db, admin_id))


@router.patch("/admins/{admin_id}")
async def update_admin(
    admin_id: uuid.UUID,
    body: UpdateAdminRequest,
    response: Response,
    db: Db,
    service: Service,
    actor: Actor,
) -> AdminOut:
    no_store(response)
    admin = await service.update_admin(
        db,
        admin_id,
        actor=actor,
        display_name=body.display_name,
        roles=body.roles,
        is_active=body.is_active,
    )
    return admin_out(admin)


@router.post("/admins/{admin_id}/reset-password", status_code=204)
async def reset_password(
    admin_id: uuid.UUID, body: ResetPasswordRequest, db: Db, service: Service
) -> Response:
    """Sets a temporary password and ends all of the admin's sessions."""
    await service.reset_password(db, admin_id, body.new_password)
    response = Response(status_code=204)
    no_store(response)
    return response

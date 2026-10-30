from typing import Annotated

from fastapi import APIRouter, Depends, Response

from identity_api.api.auth import AdminProfile, no_store, profile_of
from identity_api.api.deps import current_admin
from identity_api.db.models import Admin

router = APIRouter(tags=["me"])


@router.get("/me")
async def me(response: Response, admin: Annotated[Admin, Depends(current_admin)]) -> AdminProfile:
    """The signed-in admin. Profile fields only: no password hash, no tokens."""
    no_store(response)
    return profile_of(admin)

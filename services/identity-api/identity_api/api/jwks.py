from typing import cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from identity_api.services.keys import KeyRing

# Services cache the key set for this long (ADR 0009).
JWKS_MAX_AGE_SECONDS = 600

router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    """The public keys that verify identity-api tokens. Public keys only, never private ones."""
    keyring = cast(KeyRing, request.app.state.keyring)
    return JSONResponse(
        keyring.jwks(), headers={"Cache-Control": f"max-age={JWKS_MAX_AGE_SECONDS}"}
    )

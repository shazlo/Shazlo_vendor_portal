import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import cast

import asyncpg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from identity_api.core.settings import Settings

logger = logging.getLogger(__name__)

CHECK_TIMEOUT_SECONDS = 2.0

ReadinessCheck = Callable[[], Awaitable[None]]

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness: the process is up. Does not touch any dependency."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    """Readiness: every dependency answers. 503 if any check fails or times out."""
    checks = cast(dict[str, ReadinessCheck], request.app.state.readiness_checks)
    results = await asyncio.gather(*(_run(name, check) for name, check in checks.items()))
    statuses = dict(results)
    ok = all(status == "ok" for status in statuses.values())
    return JSONResponse(
        {"status": "ok" if ok else "unavailable", "checks": statuses},
        status_code=200 if ok else 503,
    )


async def _run(name: str, check: ReadinessCheck) -> tuple[str, str]:
    try:
        await asyncio.wait_for(check(), CHECK_TIMEOUT_SECONDS)
    except Exception as exc:
        # No traceback: probes hit this every few seconds while a dependency is down.
        logger.warning("readiness check failed", extra={"check": name, "error": type(exc).__name__})
        return name, "unavailable"
    return name, "ok"


def default_readiness_checks(settings: Settings) -> dict[str, ReadinessCheck]:
    async def postgres() -> None:
        dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        connection = await asyncpg.connect(dsn, timeout=CHECK_TIMEOUT_SECONDS)
        try:
            await connection.execute("SELECT 1")
        finally:
            await connection.close()

    async def redis() -> None:
        client = Redis.from_url(settings.redis_url)
        try:
            await client.ping()
        finally:
            await client.aclose()

    return {"postgres": postgres, "redis": redis}

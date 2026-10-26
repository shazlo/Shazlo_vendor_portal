from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from identity_api import __version__
from identity_api.api import health
from identity_api.core.errors import register_exception_handlers
from identity_api.core.logging import configure_logging
from identity_api.core.middleware import REQUEST_ID_HEADER, RequestIdMiddleware
from identity_api.core.settings import Settings, get_settings
from identity_api.db.session import create_engine, create_sessionmaker


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    await app.state.engine.dispose()


def create_app(
    settings: Settings | None = None,
    readiness_checks: dict[str, health.ReadinessCheck] | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    # OpenAPI docs are for development; production does not serve them.
    docs_enabled = settings.env != "prod"
    app = FastAPI(
        title="identity-api",
        version=__version__,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    # The engine connects lazily, so creating the app does not need a reachable database.
    app.state.engine = create_engine(settings.database_url)
    app.state.sessionmaker = create_sessionmaker(app.state.engine)
    app.state.readiness_checks = (
        readiness_checks
        if readiness_checks is not None
        else health.default_readiness_checks(settings)
    )

    # Middleware added last runs first: request ID wraps CORS so even CORS answers carry an ID.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
        expose_headers=[REQUEST_ID_HEADER],
    )
    app.add_middleware(RequestIdMiddleware)
    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(APIRouter(prefix="/v1"))  # feature routers are added here
    return app

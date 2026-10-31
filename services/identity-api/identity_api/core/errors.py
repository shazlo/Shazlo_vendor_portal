import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from identity_api.core.middleware import REQUEST_ID_HEADER

logger = logging.getLogger("identity_api.errors")


def error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Every error leaves the API as {"error": {code, message, request_id, details?}}."""
    request_id = getattr(request.state, "request_id", None)
    body: dict[str, Any] = {"code": code, "message": message, "request_id": request_id}
    if details is not None:
        body["details"] = jsonable_encoder(details)
    response = JSONResponse({"error": body}, status_code=status_code, headers=headers)
    if request_id:
        # Unhandled errors are answered outside the request-ID middleware, so set the header here.
        response.headers[REQUEST_ID_HEADER] = request_id
    return response


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        phrase = HTTPStatus(exc.status_code).phrase
        code = phrase.lower().replace(" ", "_")
        message = exc.detail if isinstance(exc.detail, str) else phrase
        return error_response(
            request,
            exc.status_code,
            code,
            message,
            headers=dict(exc.headers) if exc.headers else None,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(
            request, 422, "validation_error", "Request validation failed", details=exc.errors()
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled exception", exc_info=exc)
        return error_response(request, 500, "internal_error", "Internal server error")

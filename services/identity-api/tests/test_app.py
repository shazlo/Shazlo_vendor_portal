import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from identity_api.api import health
from identity_api.app import create_app
from identity_api.core.settings import Settings


async def _ok() -> None:
    return None


async def _fail() -> None:
    raise ConnectionError("down")


async def _hang() -> None:
    await asyncio.sleep(60)


def make_client(
    settings: Settings, checks: dict[str, health.ReadinessCheck] | None = None
) -> TestClient:
    app = create_app(settings, readiness_checks=checks if checks is not None else {"x": _ok})

    class Body(BaseModel):
        name: str

    @app.post("/echo")
    async def echo(body: Body) -> Body:
        return body

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("secret detail")

    return TestClient(app, raise_server_exceptions=False)


def test_health_is_ok_and_has_request_id(settings: Settings) -> None:
    response = make_client(settings).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert len(response.headers["X-Request-ID"]) == 32


def test_incoming_request_id_is_echoed(settings: Settings) -> None:
    response = make_client(settings).get("/health", headers={"X-Request-ID": "trace-123"})
    assert response.headers["X-Request-ID"] == "trace-123"


def test_unsafe_request_id_is_replaced(settings: Settings) -> None:
    response = make_client(settings).get("/health", headers={"X-Request-ID": "bad id!"})
    assert response.headers["X-Request-ID"] != "bad id!"


def test_ready_ok_when_all_checks_pass(settings: Settings) -> None:
    response = make_client(settings, {"postgres": _ok, "redis": _ok}).get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"postgres": "ok", "redis": "ok"}}


def test_ready_503_when_a_dependency_fails(settings: Settings) -> None:
    response = make_client(settings, {"postgres": _ok, "redis": _fail}).get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"postgres": "ok", "redis": "unavailable"}


def test_ready_503_when_a_dependency_hangs(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health, "CHECK_TIMEOUT_SECONDS", 0.05)
    response = make_client(settings, {"postgres": _hang}).get("/ready")
    assert response.status_code == 503


def test_ready_503_with_real_checks_when_nothing_is_listening(settings: Settings) -> None:
    unreachable = settings.model_copy(
        update={
            "database_url": "postgresql://u:p@127.0.0.1:1/db",
            "redis_url": "redis://127.0.0.1:1/0",
        }
    )
    response = TestClient(create_app(unreachable)).get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"postgres": "unavailable", "redis": "unavailable"}


def test_not_found_uses_error_shape(settings: Settings) -> None:
    response = make_client(settings).get("/nope")
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert error["request_id"] == response.headers["X-Request-ID"]


def test_validation_error_uses_error_shape(settings: Settings) -> None:
    response = make_client(settings).post("/echo", json={})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["loc"] == ["body", "name"]


def test_unhandled_error_is_hidden_but_traceable(settings: Settings) -> None:
    response = make_client(settings).get("/boom")
    assert response.status_code == 500
    assert response.json()["error"]["message"] == "Internal server error"
    assert "secret detail" not in response.text
    assert response.headers["X-Request-ID"] == response.json()["error"]["request_id"]


def test_docs_served_outside_prod_only(settings: Settings) -> None:
    assert make_client(settings).get("/docs").status_code == 200
    prod = make_client(settings.model_copy(update={"env": "prod"}))
    assert prod.get("/docs").status_code == 404
    assert prod.get("/openapi.json").status_code == 404


def test_cors_allows_only_configured_origins(settings: Settings) -> None:
    client = make_client(settings)
    allowed = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert allowed.headers["access-control-allow-credentials"] == "true"
    denied = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in denied.headers


def test_logs_are_json_with_request_id(
    settings: Settings, capsys: pytest.CaptureFixture[str]
) -> None:
    make_client(settings).get("/health", headers={"X-Request-ID": "log-me"})
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    access = next(line for line in lines if line["logger"] == "identity_api.access")
    assert access["request_id"] == "log-me"
    assert access["path"] == "/health"
    assert access["status"] == 200

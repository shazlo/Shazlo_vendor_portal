# services

FastAPI services. Each has its own `pyproject.toml`, package and `tests/`.

## Tooling (enforced by CI)

| Tool | Config | Command (run inside a service dir) |
|---|---|---|
| ruff lint | `services/ruff.toml` (shared, extended by each service) | `ruff check .` |
| ruff format | same | `ruff format --check .` |
| mypy (strict) | `[tool.mypy]` in the service's `pyproject.toml` | `mypy` |
| pytest | `[tool.pytest.ini_options]` in the service's `pyproject.toml` | `pytest` |

Setup: `python -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'`. A service that uses `packages/py-auth` installs it first: `pip install -e '../../packages/py-auth[fastapi]' --config-settings editable_mode=compat`.

Tests that need Postgres use the `*_test` databases created by the root `docker-compose.yml` and read the URL from `DATABASE_URL` (CI sets it to a Postgres service container).

# identity-api

FastAPI service for Shazlo-One admin users, roles and JWT issuing (RS256, JWKS). See [ADR 0009](../../docs/adr/0009-auth-model.md) and [Phase 1](../../docs/ROADMAP.md#phase-1-identity-api-shazlo-one-admins).

Status: scaffold. The app factory, settings, logging, error handling and health endpoints are in place; auth endpoints come in the other Phase 1 issues.

## Run locally

```sh
cd services/identity-api
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env      # then fill in DATABASE_URL and REDIS_URL
uvicorn identity_api.main:app --reload --port 8001
```

The app refuses to start if `DATABASE_URL` or `REDIS_URL` is missing. OpenAPI docs are at `/docs` unless `ENV=prod`.

## Layout

```
identity_api/
  app.py        create_app() factory (settings and readiness checks can be injected in tests)
  main.py       `app = create_app()` for uvicorn
  api/          routers (health now; auth and admins later)
  core/         settings, JSON logging, request-ID middleware, error handlers
  db/           models, declarative base (constraint naming convention), async engine and sessions
  migrations/   Alembic env and versions (runs on a sync psycopg engine)
  services/     business logic, free of HTTP concerns
```

## Settings

Read from the environment (and `.env`). Names are the upper-case field names. Full list with comments in [`.env.example`](.env.example).

| Setting | Default | Notes |
|---|---|---|
| `DATABASE_URL` | none (required) | `postgresql://` or `postgresql+asyncpg://` |
| `REDIS_URL` | none (required) | `redis://` or `rediss://` |
| `ENV` | `dev` | `dev`, `test` or `prod`; `prod` turns off `/docs` |
| `LOG_LEVEL` | `INFO` | |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | comma separated; credentials allowed for these only |
| `COOKIE_SECURE` / `COOKIE_SAMESITE` / `COOKIE_DOMAIN` | `true` / `strict` / unset | refresh-token cookie |
| `JWT_ISSUER` | `http://localhost:8001` | `iss` claim |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | |
| `REFRESH_TOKEN_TTL_DAYS` / `REFRESH_FAMILY_MAX_DAYS` | `7` / `30` | |

## Database

Async SQLAlchemy 2 with `asyncpg` for the app; Alembic runs on a sync engine (psycopg 3). `DATABASE_URL` may use `postgresql://`, `postgresql+asyncpg://` or `postgresql+psycopg://`: each side picks its own driver.

| Table | Notes |
|---|---|
| `admins` | UUID `id`; `email` unique and stored lower-cased (a check constraint enforces it, so uniqueness is case-insensitive in the DB); `password_hash`, `display_name`, `is_active`, `must_change_password` (default true), `created_at`, `updated_at`, `last_login_at` |
| `roles` | `name` primary key (`super_admin`, `vendor_reviewer`, later `<area>_<role>`), `description` |
| `admin_roles` | many to many; deleting an admin removes its links, a role still assigned cannot be deleted |

Migration `0001` seeds the `super_admin` and `vendor_reviewer` roles. Refresh tokens live in Redis (ADR 0009), so there is no token table.

```sh
alembic upgrade head                 # uses DATABASE_URL (or .env)
alembic downgrade base
alembic revision --autogenerate -m "<message>"   # then review the generated file
alembic check                        # fails if models and migrations differ
```

In a container: `docker compose exec identity-api alembic upgrade head`.

## Behaviour worth knowing

- `GET /health` is liveness only. `GET /ready` checks Postgres and Redis (2 second timeout each) and returns 503 if either fails.
- Every response has an `X-Request-ID` header. A sane incoming value is reused; it is also in every log line.
- Logs are one JSON object per line on stdout.
- Errors always look like `{"error": {"code", "message", "request_id", "details"?}}`. Unhandled errors return a generic message; details go to the log only.

## Checks (run by CI)

```sh
ruff check . && ruff format --check . && mypy && pytest
```

Database tests run against real Postgres from `DATABASE_URL` and are skipped when it is unset (CI sets it). Locally, point it at the `identity_test` database from the root docker-compose:

```sh
DATABASE_URL=postgresql://shazlo:<password>@localhost:5432/identity_test pytest
```

The suite drops and recreates the schema (`alembic downgrade base` then `upgrade head`) and refuses any database whose name does not contain `test`. Each test runs in a transaction that is rolled back, so tests share no rows.

## Docker

```sh
docker build -t identity-api services/identity-api
```

Runs as a non-root user on port 8001 and has a healthcheck on `/health`.

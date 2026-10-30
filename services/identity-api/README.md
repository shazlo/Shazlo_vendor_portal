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
  db/           models and sessions (async SQLAlchemy 2, added with the schema)
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

## Behaviour worth knowing

- `GET /health` is liveness only. `GET /ready` checks Postgres and Redis (2 second timeout each) and returns 503 if either fails.
- Every response has an `X-Request-ID` header. A sane incoming value is reused; it is also in every log line.
- Logs are one JSON object per line on stdout.
- Errors always look like `{"error": {"code", "message", "request_id", "details"?}}`. Unhandled errors return a generic message; details go to the log only.

## Checks (run by CI)

```sh
ruff check . && ruff format --check . && mypy && pytest
```

## Docker

```sh
docker build -t identity-api services/identity-api
```

Runs as a non-root user on port 8001 and has a healthcheck on `/health`.

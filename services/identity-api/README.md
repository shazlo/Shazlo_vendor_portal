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

Create a signing key once with `python -m identity_api.cli generate-key` (writes `.keys/<kid>.pem`, git-ignored) and set `JWT_KEYS_DIR=.keys`.

The app refuses to start if `DATABASE_URL`, `REDIS_URL` or the JWT keys are missing. OpenAPI docs are at `/docs` unless `ENV=prod`.

## Layout

```
identity_api/
  app.py        create_app() factory (settings and readiness checks can be injected in tests)
  main.py       `app = create_app()` for uvicorn
  api/          routers (health, JWKS; auth and admins later)
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
| `JWT_KEYS_DIR` / `JWT_KEYS` | none (one is required) | RS256 keys: a directory of `<kid>.pem` files and/or JSON `{"<kid>": "<PEM>"}`; the app refuses to start without a key |
| `AUDIENCE_ROLES` | `identity-api` and `vendor-api` for `super_admin` and `vendor_reviewer` | JSON `{"<service>": ["<role>", ...]}`; see Auth endpoints |
| `JWT_SIGNING_KID` | the only key, if there is just one | which key signs; the others are published in the JWKS only |
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

## Tokens and keys

- `TokenIssuer` (`services/tokens.py`) signs RS256 access tokens: `iss`, `sub`, `aud` (one service), `roles`, `iat`, `exp` (15 minutes), `jti`, with the `kid` in the header. No email or name goes into the token.
- `GET /.well-known/jwks.json` serves the public keys with `Cache-Control: max-age=600`. It is built from public keys only.
- Keys are RSA 2048-bit or larger. A key that is only published (not signing) may be configured as a public PEM.
- Rotation is a configuration change; follow [the runbook](../../docs/runbooks/jwt-key-rotation.md).

## Auth endpoints

| Endpoint | Notes |
|---|---|
| `POST /v1/auth/login` | `{email, password}` returns `{access_token, token_type, expires_in, must_change_password, admin}` and sets the refresh cookie. Unknown email, wrong password and inactive admin all give the same `401 invalid_credentials`. |
| `POST /v1/auth/refresh` | Reads the cookie, rotates it and returns the same body as login. A token that was already used revokes its whole family. A rejected token is answered with `401` and the cookie is cleared. |
| `POST /v1/auth/logout` | Revokes the cookie's family and clears the cookie. Always `204`. |
| `POST /v1/auth/token` | Bearer identity-api token plus `{"audience": "<service>"}`. Returns a 15-minute token for that one service (`{access_token, token_type, expires_in, audience}`), no refresh token. `400 unknown_audience` if the service is not in `AUDIENCE_ROLES`, `403 audience_not_allowed` if none of the admin's roles is listed for it. |
| `GET /v1/me` | The signed-in admin: id, email, display name, roles, `must_change_password`. Never hashes or tokens. |
| `GET /v1/roles` | `super_admin` only (like every endpoint below): the roles that exist, `[{name, description}]`. |
| `GET /v1/admins` | Paged list `{items, total, limit, offset}`. Query: `limit` (1-100, default 25), `offset`, `q` (email or name contains), `role`, `is_active`. |
| `POST /v1/admins` | `{email, display_name, password, roles}` creates an admin with `must_change_password` set. `201`, `409 email_taken` (any letter case), `422 weak_password` / `unknown_role`. |
| `GET /v1/admins/{id}` | One admin, `404 admin_not_found` if unknown. |
| `PATCH /v1/admins/{id}` | Any of `display_name`, `roles`, `is_active`. Deactivating ends all the admin's refresh families. Roles reach tokens when the next one is issued (within 15 minutes). `409 cannot_deactivate_self`, `409 last_super_admin` (the last active `super_admin` cannot be deactivated or lose the role). |
| `POST /v1/admins/{id}/reset-password` | `{new_password}` sets a temporary password, sets `must_change_password` and ends all the admin's refresh families. `204`. |
| `POST /v1/auth/change-password` | Bearer token plus `{current_password, new_password}`. Ends every refresh family of the admin and starts a new session (new cookie and token). |

- **Refresh tokens** are 256-bit random values. They exist only in the `HttpOnly` cookie (`Secure` and `SameSite` from settings, path `/v1/auth`); never in a body or a log. Redis holds only their SHA-256 hash (`rt:<hash>`) plus the family (`rf:<id>`, hard limit 30 days) and the admin's family set (`ra:<admin>`). A token lives 7 days and never outlives its family.
- **First login:** an admin with `must_change_password` gets an access token with **no roles** and a `must_change_password` claim. Services grant it nothing, and identity-api's own `current_admin` dependency answers `403 password_change_required`. Only `change-password` accepts it. The new token returned by `change-password` is a normal one.
- **Audiences:** `AUDIENCE_ROLES` (JSON in the environment) maps each service name to the roles allowed to get a token for it, and must include `identity-api`. Adding a service is a settings change only. Roles are read from the database at exchange time, and a token for another audience is rejected by identity-api's own `current_admin` dependency.
- `api/deps.py` has the dependencies later endpoints use: `current_admin` (active admin, password already changed) and `current_admin_pending_password`.
- Concurrent refreshes with the same token (two tabs at once) count as reuse and end the session; the shell must refresh from one place (ADR 0009).
- Rate limiting is a separate issue (#53).

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

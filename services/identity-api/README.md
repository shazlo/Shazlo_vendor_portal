# identity-api

The sign-in service for Shazlo-One admins. It stores admins and roles, signs RS256 access tokens, publishes the public keys as a JWKS, keeps admin sessions (refresh tokens) in Redis and rate limits the auth endpoints. Other services verify its tokens locally with [`packages/py-auth`](../../packages/py-auth/README.md), without calling it per request.

- Design: [ADR 0009, the auth model](../../docs/adr/0009-auth-model.md) (tokens, audiences, refresh families, roles, rotation).
- Operations: [runbook: rotate the JWT signing key](../../docs/runbooks/jwt-key-rotation.md).
- Scope: [Phase 1 of the roadmap](../../docs/ROADMAP.md#phase-1-identity-api-shazlo-one-admins).

## Run locally

You need Python 3.12+ and Docker. All commands are copy-paste; replace the values in angle brackets.

**1. Postgres and Redis**, from the repository root:

```sh
cp .env.example .env              # set POSTGRES_PASSWORD
docker compose up -d postgres redis
docker compose ps                 # both report "healthy"
```

The first start creates the `identity` and `identity_test` databases.

**2. Install**, in `services/identity-api`:

```sh
cd services/identity-api
python -m venv .venv && . .venv/bin/activate
pip install -e '../../packages/py-auth[fastapi]' --config-settings editable_mode=compat   # shared package first
pip install -e '.[dev]'
cp .env.example .env
```

In `.env`, put your `POSTGRES_PASSWORD` into `DATABASE_URL` (the database is `identity`). If you will call the API with curl or from Safari over plain `http`, also set `COOKIE_SECURE=false` (see Cookies and CORS below). The rest of the defaults work.

**3. Key, schema, first admin**:

```sh
python -m identity_api.cli generate-key       # writes .keys/<kid>.pem (git-ignored); .env already has JWT_KEYS_DIR=.keys
alembic upgrade head
SEED_ADMIN_EMAIL=admin@shazlo.test SEED_ADMIN_PASSWORD='<at least 12 characters>' python -m identity_api.cli seed
```

The seed creates the roles and one `super_admin` who must change the password at the first login. It is safe to run again: an existing admin is never touched. Without the two variables it asks in the terminal.

**4. Start and sign in**:

```sh
uvicorn identity_api.main:app --reload --port 8001
```

```sh
# log in: the response has "must_change_password": true and an access_token
curl -s -c jar -b jar localhost:8001/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email": "admin@shazlo.test", "password": "<the seed password>"}'

# set your own password with that access_token; the response has a normal access_token
curl -s -c jar -b jar localhost:8001/v1/auth/change-password \
  -H "authorization: Bearer <access_token>" -H 'content-type: application/json' \
  -d '{"current_password": "<the seed password>", "new_password": "<a new password>"}'

# who am I?
curl -s localhost:8001/v1/me -H "authorization: Bearer <the new access_token>"
```

Interactive docs: <http://localhost:8001/docs> (OpenAPI JSON at `/openapi.json`). They are served unless `ENV=prod`. In Swagger, press Authorize and paste an access token to try the other endpoints.

The app refuses to start if `DATABASE_URL`, `REDIS_URL` or the JWT keys are missing.

## Cookies and CORS (local development)

- The **refresh token** is an `HttpOnly` cookie on `/v1/auth` and is never in a response body. The browser keeps it; JavaScript only ever holds the 15-minute access token.
- **`COOKIE_SECURE=true`** (the default) works on `http://localhost` in Chrome and Firefox, which treat localhost as secure. Safari and curl do not, so set `COOKIE_SECURE=false` locally for them. Never in production.
- **`SameSite=Strict`**: the shell (`http://localhost:5173`) and this API (`http://localhost:8001`) are the same site because ports do not count, so the cookie is sent. In production they share a parent domain: set `COOKIE_DOMAIN` (for example `shazlo.store`).
- **CORS**: the shell's exact origin must be in `CORS_ALLOWED_ORIGINS` (comma separated; no wildcard, because credentials are allowed), and its requests need `credentials: "include"` so the cookie is sent to `/v1/auth/refresh` and `/v1/auth/logout`.
- Refresh from **one place** in the shell: two tabs refreshing with the same token at once count as reuse and end the session.

## Layout

```
identity_api/
  app.py        create_app() factory (settings and readiness checks can be injected in tests)
  main.py       `app = create_app()` for uvicorn
  api/          routers: health, JWKS, auth, me, admins; deps.py (current_admin, require_role)
  core/         settings, JSON logging, request-ID middleware, error handlers
  db/           models, declarative base (constraint naming convention), async engine and sessions
  migrations/   Alembic env and versions (runs on a sync psycopg engine)
  services/     business logic, free of HTTP concerns (auth, admins, tokens, keys, refresh tokens, rate limits)
  cli.py        `seed` and `generate-key`
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
| `RATE_LIMIT_LOGIN_IP` / `RATE_LIMIT_LOGIN_EMAIL` | `20/60` / `5/900` | `<limit>/<window seconds>`; see Rate limiting |
| `RATE_LIMIT_REFRESH_IP` / `RATE_LIMIT_REFRESH_SESSION` | `60/60` / `20/60` | |
| `RATE_LIMIT_TOKEN_IP` / `RATE_LIMIT_TOKEN_ADMIN` | `120/60` / `60/60` | |
| `RATE_LIMIT_CHANGE_PASSWORD_ADMIN` | `5/900` | |
| `RATE_LIMIT_FAIL_CLOSED` | `login,change_password` | endpoints that answer 503 when Redis is down; the others skip the limit |
| `RATE_LIMIT_HMAC_KEY` | random per process (required in `prod`) | keys the hashes of emails and IPs in Redis; every instance must share it |
| `TRUSTED_PROXIES` | none | CIDRs of the reverse proxies whose `X-Forwarded-For` is believed, comma separated |

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

## Endpoints

The live reference is the OpenAPI document at `/docs` (dev). Every error is `{"error": {"code", "message", "request_id"}}`.

| Endpoint | Notes |
|---|---|
| `GET /health` / `GET /ready` | Liveness; readiness (Postgres and Redis). |
| `GET /.well-known/jwks.json` | The public keys, `Cache-Control: max-age=600`. |
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
- `api/deps.py` has the dependencies later endpoints use: `current_admin` (active admin, password already changed), `current_admin_pending_password` and `require_role(...)`. Tokens are verified by `packages/py-auth` (`shazlo-auth`), the same verifier other services use, here fed with this service's own keys. `require_role` is the shared one (`super_admin` always passes) but reads roles from the database, so a role change applies to this API at once.
- Concurrent refreshes with the same token (two tabs at once) count as reuse and end the session; the shell must refresh from one place (ADR 0009).

## Rate limiting

Fixed-window counters in Redis (`rl:<endpoint>:<scope>:<hash>`), so the limits hold across instances. The limiter is a small interface (`services/rate_limit.py`), so the store can change. Over a limit the answer is `429 rate_limited` with `Retry-After` (seconds until the window resets, taken from the key's TTL). A fixed window lets a burst of up to twice the limit pass across a window boundary, which is fine for brute-force protection.

| Endpoint | Limited by |
|---|---|
| `POST /v1/auth/login` | client IP, and the email (trimmed, lower-cased) |
| `POST /v1/auth/refresh` | client IP, and the refresh family (when the cookie is valid) |
| `POST /v1/auth/token` | client IP, and the admin |
| `POST /v1/auth/change-password` | the admin |

- **Login email counter:** counted before the password is checked, so parallel guesses cannot slip past, and cleared by a successful login. In effect it limits failed attempts for one email, from any IP. Unknown emails are counted the same way, so the response does not reveal whether an email exists.
- **A rate-limited refresh keeps its cookie:** the limit says nothing about the token.
- **No plain subjects in Redis:** emails, IPs, admin IDs and families are hashed with HMAC-SHA256 under `RATE_LIMIT_HMAC_KEY`. The key matters because emails are guessable: a plain hash could be reversed from a Redis dump.
- **Client IP:** the TCP peer, unless it is in `TRUSTED_PROXIES`. Then `X-Forwarded-For` is read from the right and the first address that is not a trusted proxy is the client; what the client wrote further left is ignored. Without `TRUSTED_PROXIES` the header is never read. Behind a load balancer, list its network, or every client shares one IP and one limit.
- **Redis down:** endpoints in `RATE_LIMIT_FAIL_CLOSED` (default `login` and `change_password`: password guessing must stay limited) answer `503 rate_limiter_unavailable`. The others (`refresh`, `token`) skip the limit and log a warning, so signed-in admins keep working. Refresh and login need Redis for sessions anyway; token exchange does not.

## Behaviour worth knowing

- `GET /health` is liveness only. `GET /ready` checks Postgres and Redis (2 second timeout each) and returns 503 if either fails.
- Every response has an `X-Request-ID` header. A sane incoming value is reused; it is also in every log line.
- Logs are one JSON object per line on stdout.
- Errors always look like `{"error": {"code", "message", "request_id", "details"?}}`. Unhandled errors return a generic message; details go to the log only.

## Checks (run by CI)

```sh
ruff check . && ruff format --check . && mypy && pytest
```

Database tests run against real Postgres from `DATABASE_URL` and are skipped when it is unset (CI sets it). The end-to-end test (`tests/test_e2e_auth.py`) also needs a real Redis in `REDIS_URL`, and **empties that Redis database after each test**: use a database other than 0. Locally, with the root docker-compose running:

```sh
DATABASE_URL=postgresql://shazlo:<password>@localhost:5432/identity_test \
REDIS_URL=redis://localhost:6379/1 pytest
```

The suite drops and recreates the schema (`alembic downgrade base` then `upgrade head`) and refuses any database whose name does not contain `test`. Each test runs in a transaction that is rolled back, so tests share no rows.

## Docker

```sh
docker build -f services/identity-api/Dockerfile -t identity-api .
```

Run it from the repository root: the build context must include `packages/py-auth`.

Runs as a non-root user on port 8001 and has a healthcheck on `/health`.

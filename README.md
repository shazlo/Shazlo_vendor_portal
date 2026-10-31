# Shazlo

Shazlo is being split into microservices that feed a central consumer application (separate repo). This repo holds:

- **Vendor Portal**: vendors sign up, personalise their brand page and list products. Submissions stay *pending* until an admin reviews them.
- **Shazlo-One**: one admin shell that hosts every microservice's admin UI in an iframe. Admins approve or reject vendor submissions; only approved content is published to the central app.

Plan, phases and decisions: [docs/ROADMAP.md](docs/ROADMAP.md). Architecture decisions: [docs/adr](docs/adr).

## Architecture

```
 Vendor ──► vendor-portal ──► vendor-api ──► Postgres
                                  ▲   │
 Admin ──► shazlo-one ──iframe──► vendor-admin
              │                       │ (JWT via postMessage)
              └──► identity-api ◄─────┘ (JWKS)
                                  │
                       outbox ──► central app (HMAC-signed push)
```

## Repo layout

| Path | What it is |
|---|---|
| `services/identity-api/` | FastAPI: admin users, roles, JWT (RS256) + JWKS |
| `services/vendor-api/` | FastAPI: vendors, brand profiles, products, assets, reviews, publishing |
| `apps/vendor-portal/` | React + TS: vendor-facing app |
| `apps/shazlo-one/` | React + TS: admin shell (login, nav, iframe host) |
| `apps/vendor-admin/` | React + TS: vendor review module, loaded in a Shazlo-One iframe |
| `packages/ui/` | Shared MUI theme and tokens |
| `packages/py-auth/` | Shared Python package: access-token verifier, JWKS client, FastAPI `require_role` |
| `docs/` | Roadmap and ADRs |
| `app/`, `backend/` | **Legacy** consumer landing/waitlist, Express + MongoDB. Untouched until Phase 8 |

The new folders are placeholders until their phase starts; see the roadmap.

## Local development

Postgres 16 runs in docker-compose:

```bash
cp .env.example .env        # then set POSTGRES_PASSWORD
docker compose up -d
docker compose ps           # postgres should report "healthy"
```

On first start it creates one database per service plus a test database for each: `identity`, `identity_test`, `vendor`, `vendor_test`. Connection string pattern: `postgresql://<user>:<password>@localhost:5432/<db>`.

The init script runs only when the data volume is created. To recreate the databases: `docker compose down -v && docker compose up -d` (this deletes all local data).

For the legacy apps, see `app/README.md` and `backend/README.md` and copy each `.env.example` to `.env`.

## Workflow

Each roadmap phase is a GitHub milestone. Each issue gets a branch named `phase-N/<issue#>-<slug>` and a PR with `Closes #N`.

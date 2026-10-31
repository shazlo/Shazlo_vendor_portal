# Vendor Portal + Shazlo-One: rewrite roadmap

## Context
Shazlo is being split into microservices that feed a central consumer application. The central app lives in a separate repo and is not built here. This roadmap covers two things:

- **Vendor Portal**: vendors sign up, personalise their brand page and list products. Everything a vendor submits stays *pending* until an admin reviews it.
- **Shazlo-One**: one admin shell that hosts the admin UI of every microservice. The Vendor Portal's admin module lives inside it. Admins review what vendors submit (brand page content, images, products) and approve or reject it. Only approved content is sent to the central app.

The current code in this repo has the right ideas, but very little of it can be kept as code:

- `app/` is React in plain JavaScript; `backend/` is Express + MongoDB.
- There is no authentication. Admin endpoints are public, and the approver ID is hardcoded in the frontend.
- Brand pages can't be personalised, and only products can be approved.
- Nothing sends approved content to the central app.
- API hosts are hardcoded in three places.
- Build artifacts such as `backend/node_modules` are committed.

We are rewriting it in phases. Each phase is a GitHub milestone, and its issues are created only when that phase starts.

## Decisions
| Area | Choice |
|---|---|
| Frontends | React + TypeScript (Vite) |
| Services | FastAPI |
| Database | PostgreSQL |
| Media | Cloudinary (signed direct uploads) |
| Admin micro-frontends | Shazlo-One embeds each service's admin UI in an **iframe** |
| Code and issues | This repo (`shazlo/Shazlo`) |

## Repo layout
New code lives beside the legacy code:

```
Shazlo/
  app/, backend/            legacy; untouched until Phase 8 (app/ also hosts the consumer landing/waitlist)
  services/
    identity-api/           FastAPI: Shazlo-One admin users, roles, JWT (RS256) + JWKS
    vendor-api/             FastAPI: vendors, brand profiles, products, assets, reviews, publishing
  apps/
    vendor-portal/          React+TS: vendor-facing app
    shazlo-one/             React+TS: admin shell (login, nav, iframe host)
    vendor-admin/           React+TS: vendor review module, loaded in a Shazlo-One iframe
  packages/ui/              shared MUI theme/tokens (black #000 / gold #FFD700, Voyage font)
  docker-compose.yml        Postgres + services for local dev
```

## What carries over from the legacy code
These are used as reference only. None of the code is reused.

- Brand fields: `backend/models/Brand.js`.
- Product fields and the pending/approved/rejected states: `backend/models/Product.js`.
- Cloudinary upload stream: `backend/routes/upload.js`. It becomes signed direct uploads.
- Excel catalog columns: `app/src/components/CatalogUpload.jsx`.
- Approval UI layout (stat cards, status filter, per-seller tables, detail dialog): `app/src/AdminPortal.jsx`.
- Vendor dashboard sections: `app/src/Seller.jsx`.

## Phases
Each phase matches a milestone in this repo. The bullets are the proposed scope; the actual issues are filed when the phase starts.

### Phase 0: Foundation & security hygiene
- Repo hygiene: untrack local env files and `node_modules`, fix `.gitignore`, and add `.env.example` files.
- Create the folder layout above and a root architecture README.
- Add `docker-compose.yml` with Postgres 16.
- CI: ruff + mypy + pytest for services; eslint + tsc + vitest for apps.
- Shared `packages/ui` theme.
- ADRs: iframe protocol, auth model, central-app publishing contract.

### Phase 1: Identity API (Shazlo-One admins)
- FastAPI scaffold: pydantic-settings, SQLAlchemy 2 + Alembic, structured logging, `/health` and `/ready`; Redis and identity-api in docker-compose.
- `admins` and `roles` tables. Roles are `super_admin` and `vendor_reviewer`, extensible per service.
- Argon2 hashes and a seed CLI for the first `super_admin`, who must change the password at the first login.
- RS256 signing keys, `/.well-known/jwks.json` and a [key-rotation runbook](runbooks/jwt-key-rotation.md).
- Login, refresh (rotating refresh tokens in Redis, reuse detection), logout and change-password.
- Token exchange (`POST /v1/auth/token`): a 15-minute token for one service, by the roles allowed for it. `GET /v1/me`.
- Admin user management (super_admin only): list, create, update, deactivate, reset password, `GET /v1/roles`.
- Rate limiting on auth endpoints (Redis), with trusted-proxy handling and a per-endpoint fail-open or fail-closed choice.
- `packages/py-auth`: the shared token verifier, JWKS client and `require_role` that every service uses.
- End-to-end test of the whole flow against Postgres and Redis, including key rotation with a token in flight.

### Phase 2: Vendor API core
- FastAPI scaffold using the same conventions as identity-api.
- Schema and migrations:
  - `vendors`: unique email; status pending/approved/rejected/suspended.
  - `vendor_users`.
  - `brand_profiles`: separate draft and published versions.
  - `products`: SKU unique per vendor.
  - `assets`.
  - `reviews`.
- Vendor auth: signup, login, refresh, email verification, and a set-password invite flow.
- Admin auth that verifies identity-api JWTs through JWKS. The reviewer is always taken from the token.
- Tests for auth and vendor data isolation.

### Phase 3: Vendor API catalog, media & review
- Brand profile: edit draft, submit for review, read the published version.
- Products CRUD. Editing an approved product creates a pending revision instead of changing the live one.
- Cloudinary signed uploads (per-vendor folder, size and type limits) and asset registration.
- Bulk Excel/CSV import with a validation report for each row.
- Review queue, draft-vs-published diff, approve, and reject with a required reason. Every decision is recorded in an audit trail.
- Approve, reject or suspend vendor accounts.

### Phase 4: Central-app publishing
- Transactional outbox, written in the same transaction as the approval.
- Publisher worker: HMAC-signed pushes to `CENTRAL_API_URL`, idempotency keys, retries with backoff, and a dead-letter status.
- Unpublish and withdraw events.
- Stub central receiver for local dev, plus a contract doc to align with the central-app team.

### Phase 5: Vendor Portal web
- Scaffold: Vite, React Router, TanStack Query, typed API client, `VITE_VENDOR_API_URL`.
- Signup, login, verify and set-password screens, with route guards.
- Dashboard shell with a route for each section.
- Brand page editor with live preview and submit for review.
- Products: list, create/edit form, image upload, and bulk import with an error report.
- Submission status, showing the admin's reasons.

### Phase 6: Shazlo-One shell
- Scaffold, admin login against identity-api, and session handling.
- Module registry and a nav that only shows the modules an admin's roles allow.
- Iframe host with a postMessage protocol:
  - The child sends `ready`, and the shell replies with `auth` and a short-lived token.
  - Messages go only to the registered origin.
  - Token refresh and navigation/title sync.
  - The child can send `logout` and `toast` to the shell.
- Admin user management UI.

### Phase 7: Vendor admin module
- Scaffold. It accepts auth only through postMessage from the Shazlo-One origin and sets `Content-Security-Policy: frame-ancestors`.
- Review queue with stats and filters.
- Item review: brand-page preview, images, product details, diff, and approve/reject with a reason.
- Vendor management.
- Publishing status for each item, with retry.
- Playwright end-to-end smoke test.

### Phase 8: Migration & cutover
- Migrate `brands` and `products` from MongoDB to Postgres.
- Send invite emails so migrated vendors can set passwords.
- Deploy services and apps with per-environment config and domains.
- Remove the legacy seller/crm routes from `app/` and the vendor/admin parts of `backend/`. Keep the consumer landing/waitlist until it gets its own migration.

## How we work
1. All phases exist as milestones.
2. When a phase starts, its issues are drafted, reviewed, and then filed under its milestone.
3. Each issue gets its own branch (`phase-N/<issue#>-<slug>`) and a PR that references `Closes #N`.
4. Once a phase is closed, the next phase's scope is adjusted for anything learned, and its issues are filed.

## Open items
- Central-app ingestion contract (endpoint, payload, auth). Phase 4 starts with a stub.
- Hosting for the FastAPI services and Postgres. Needed by Phase 8.
- Whether the service behind `/v1/seller-signup/` (called by legacy `BrandOnboarding.jsx`) holds vendor data we must migrate.

## Definition of done
- Every PR has green CI.
- Services are tested against a Postgres test DB for:
  - auth
  - vendor isolation
  - review state transitions
  - outbox → publisher, against the stub receiver
- End-to-end, run locally with docker-compose:
  1. A vendor signs up, edits their brand page, adds a product with images, and submits.
  2. An admin logs into Shazlo-One and opens the Vendor module.
  3. The admin approves one item and rejects another with a reason.
  4. The stub central receiver gets exactly the approved payload, and the vendor sees both statuses.

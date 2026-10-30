# 0009. Auth model: RS256 JWTs, JWKS and roles for Shazlo-One and the vendor API

- Status: proposed
- Date: 2026-10-24
- Issue: #31
- Related: [ROADMAP](../ROADMAP.md) Phases 1, 2, 6 and 7; [0001 iframe postMessage protocol](0001-iframe-postmessage-protocol.md); [0004 authentication](0004-authentication.md) (partly superseded, because it describes the old vendor-admin service model)

## Context

Today no admin route checks who the caller is, and the reviewer ID is hardcoded in the frontend. The rewrite adds two kinds of sign-in:

- **Admins** of Shazlo-One (the admin shell). They are managed centrally and reach every module, such as vendor-admin, through the shell.
- **Vendors**, who use the vendor portal and only ever see their own data.

Several services must trust the same admin identity without sharing a database or a secret, so the signing key has to be public-key based. The iframe protocol (ADR 0001) needs a short-lived access token to call the shell and trusted services. The admin shell also needs a way to issue tokens to modules without reusing the browser's identity fields.

Customer sign-in (guest and account) is out of scope. It stays in Core as decided in ADR 0004.

## Decision

### Admin tokens (identity-api)

`identity-api` is the only issuer of admin tokens. They are RS256 JWTs.

| Claim | Value |
| --- | --- |
| `iss` | The identity-api base URL (a setting, for example `https://identity.shazlo.store`) |
| `sub` | The admin's UUID |
| `aud` | **One** service name, for example `vendor-api` or `identity-api` |
| `roles` | Array of role names, for example `["vendor_reviewer"]` |
| `iat`, `exp` | Issue and expiry time. `exp - iat` is 15 minutes |
| `jti` | Unique token ID, for logs and tracing |

Rules:

- **Audience per service.** A token is valid for exactly one service. A service rejects any token whose `aud` is not its own name, so a token for `vendor-api` is useless against another service.
- **Which roles get which audience** is a map in identity-api's settings. A `vendor_reviewer` can get `vendor-api` and `identity-api` tokens and nothing else. A new service adds its audience and the roles it accepts to the map.
- **No personal data beyond ids.** Email and display name are returned by login and `GET /v1/me`, not placed in the token.
- **Algorithm is pinned.** Services accept `RS256` only and reject `none`, `HS*` and any other `alg`. They check `iss`, `aud` and `exp` (30 seconds of leeway) and require `sub`, `roles` and `kid`.

### JWKS, key rotation and caching

- identity-api serves `GET /.well-known/jwks.json` with the public keys. Each key has a `kid` and every token header carries the `kid` it was signed with.
- Keys are RSA 2048-bit. The private key comes from the environment or secret store and is never committed. Local development uses a generated key.
- **Rotation every 90 days**, and immediately after any suspected leak:
  1. Add the new key to the JWKS (it is published but not used for signing yet).
  2. After at least one cache TTL (below), start signing with the new key.
  3. Keep the old key in the JWKS until every token it signed has expired (15 minutes) plus one cache TTL, then remove it.
  An emergency rotation skips the waiting and removes the old key at once. All admin sessions then end and admins sign in again.
- **Caching in services.** The JWKS response sets `Cache-Control: max-age=600`. Services cache it for 10 minutes. On a `kid` they do not know, they refetch **at most once per minute**. If a refetch fails, they keep the cache and reject unknown tokens until the next retry. This avoids a cache stampede.

### Sessions, refresh and logout

- **Two token kinds.** The access token is the JWT above. The refresh token is an **opaque random value (256 bits)**, not a JWT.
- **Lifetimes.** Access token 15 minutes. Refresh token 7 days, rotated on every use, and a token family ends 30 days after login whatever the activity.
- **Storage on the server.** identity-api stores refresh tokens and family metadata in Redis, keyed by family ID and SHA-256 token hash. Redis is the preferred store here because refresh tokens are short-lived, high-churn and already suit TTL-based expiry, fast revocation and family invalidation. A Postgres fallback is possible, but it is not the default design for this flow.
- **Rotation and reuse detection.** `POST /v1/auth/refresh` returns a new access and refresh token and marks the old refresh token used. If an already-used token comes back, the whole family is rejected and all sessions in that family are logged out. This protects against replay and token theft.
- **Storage in the browser.** The shell keeps the refresh token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to `/v1/auth` on the identity-api origin. The shell and identity-api sit on the same site, so the cookie is not sent to any other domain.
- **Tokens for modules.** The shell holds an access token for `identity-api`. For each module it calls `POST /v1/auth/token` with that token and the audience it wants, and gets a 15-minute token for the target service.
- **Logout** revokes the token family. Access tokens already issued stay valid until they expire (at most 15 minutes), which is accepted, because services verify tokens without calling identity-api on every request.
- **Deactivating an admin** revokes all their families. A change of roles applies when the next access token is issued, so within 15 minutes.
- **Passwords** use Argon2id. Login errors are the same for an unknown email and a wrong password. Login, refresh and token exchange are rate limited.

### Roles

- Roles are plain strings stored in `roles` and `admin_roles` (many to many) in identity-api, with a seed script for the first `super_admin`.
- **`super_admin`**: manages admins and roles, and passes every role check in every service.
- **`vendor_reviewer`**: reviews vendor brand profiles and products in vendor-admin.
- **Extensibility.** A new service adds roles named `<area>_<role>` through a migration or seed, and adds them to the audience map. Services check roles through one shared helper, `require_role(..)`, which reads the token and the service's role config.
- Permissions are checked in the service, on the object. Unknown or foreign objects return 404.

### Vendor auth (vendor-api)

- Vendors are **separate from admins**: `vendor_users` live in vendor-api's own database, with their own Argon2id passwords, email verification and invite flow (Phase 2). There is no shared user table.
- vendor-api issues its **own** RS256 tokens, with its own key and JWKS, `iss` set to vendor-api, `aud` `vendor-api`, `sub` the vendor user, a `vendor_id` claim and a vendor role (`owner` or `staff`).
- vendor-api keeps two route groups. `/v1/vendor/*` accepts **only** vendor-api-issued tokens. `/v1/admin/*` accepts **only** identity-api-issued tokens, verified through the JWKS. A token from one issuer cannot pass the other route group.
- **Identity always comes from the token.**
  - The reviewer on a review is the `sub` of the admin token. A `reviewer_id` in a body, query or header is ignored or rejected.
  - A vendor's `vendor_id` is the claim in their token. Every vendor query is scoped by it, and another vendor's object returns 404.

## Consequences

- Services verify tokens locally and need no call to identity-api per request. The cost is that revocation is not instant: up to 15 minutes for logout, a deactivated admin or a role change.
- The 15-minute access lifetime is longer than the "about 5 minutes" ADR 0001 assumed. The shell's refresh rule (at about 80% of the lifetime) still works, so only the numbers in ADR 0001's text changed.
- identity-api is a single point of failure for sign-in and token refresh. A token already issued keeps working, and services keep serving with cached keys, if identity-api is briefly down.
- Two issuers (identity-api and vendor-api) mean two signing keys and two JWKS to rotate. In return a vendor token can never act as an admin.
- **ADR 0004 is partly superseded.** For Shazlo-One admins and for vendors, this ADR replaces its text about the vendor-admin service issuing vendor and admin tokens and the refresh family design in the old approach.
- Follow-ups: implement in Phase 1 (identity-api) and Phase 2 (vendor-api); add a JWT verification helper that all services share; document the key rotation steps in a runbook.

## Alternatives considered

- **A hosted auth service** (Auth0, Firebase, Cognito). Less code, but a second user store, per-user pricing and a dependency for a small internal admin group. Rejected, in line with ADR 0004.
- **HS256 with a shared secret.** Every verifying service could also forge tokens. Rejected for RS256 with public keys.
- **One issuer for admins and vendors.** Simpler, but one compromise or bug would cross the admin and vendor boundary, and ADR 0007 already asks for separate identities. Rejected.
- **Opaque access tokens with introspection.** Instant revocation, but every request needs a call to identity-api. Rejected for short-lived JWTs.
- **Redis refresh families (ADR 0004).** Preferred for the operational model in this ADR because refresh tokens are short-lived, high-churn, and map naturally to TTLs and family invalidation. This adds Redis to the stack, but it is a better fit than storing every rotated token in Postgres.
- **Stateless refresh JWTs.** No server state, but no real logout or reuse detection. Rejected.
- **5-minute access tokens.** Shorter revocation lag, but more refresh traffic. 15 minutes was chosen to match ADR 0004.

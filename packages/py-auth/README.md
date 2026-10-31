# shazlo-auth

Verifies identity-api access tokens the same way in every service, so security code is not copied between them (ADR 0009). Used by `services/identity-api` and, later, `vendor-api` and the vendor-admin backend.

## Install (path dependency)

A service lists `shazlo-auth[fastapi]` in its dependencies and installs the package from the path first:

```sh
pip install -e '../../packages/py-auth[fastapi]' --config-settings editable_mode=compat
pip install -e '.[dev]'
```

`editable_mode=compat` keeps the package visible to mypy. In Docker, build from the repository root so the image can include `packages/py-auth` (see `services/identity-api/Dockerfile`).

## Use

```python
from shazlo_auth import JwksClient, TokenVerifier
from shazlo_auth.fastapi import get_current_admin, require_role

keys = JwksClient.from_url("https://identity.shazlo.store/.well-known/jwks.json")
app.state.token_verifier = TokenVerifier(
    keys, issuer="https://identity.shazlo.store", audience="vendor-api"
)


@router.get("/reviews", dependencies=[Depends(require_role("vendor_reviewer"))])
async def reviews(admin: AuthenticatedAdmin = Depends(get_current_admin)): ...
```

Create the `JwksClient` once per process, never per request: it holds the cache.

## What it checks

- **Algorithm:** `RS256` only. The header is checked before any key is looked up, so `none`, `HS*` (including an HMAC keyed with the public key) and other algorithms are refused.
- **Claims:** `iss` and `aud` must match, `exp` is checked with 30 seconds of leeway. `aud` must be exactly this service's name as one string (a list is refused). `sub` (a UUID), `roles` (a list of strings), `jti`, `iat` and the `kid` header are required.
- **Roles:** `require_role(*roles)` passes an admin who holds any of them. `super_admin` always passes. `get_current_admin` refuses a token that only allows a password change (`must_change_password`).
- **Errors:** missing or invalid token is `401` with `WWW-Authenticate: Bearer`, a missing role is `403`. Both are plain `HTTPException`s, so the service's own error handlers shape the response.

## JWKS client

| Rule | Value |
|---|---|
| Cache | 10 minutes |
| Refetch on an unknown `kid` or an expired cache | at most once per minute, whatever the traffic (successes and failures count) |
| Concurrent callers | share one fetch |
| Fetch fails | the last good keys stay in use; the next try waits for the minute. Before the first success every token is rejected |
| Bad document (no usable key) | treated as a failed fetch, so it never replaces good keys |
| Keys accepted | RSA, 2048 bits or more, `use` `sig` (or absent), `alg` `RS256` (or absent), with a `kid` |

Consequence of the one-minute bound: a token signed with a brand-new key can be rejected for up to a minute after the last fetch. ADR 0009 avoids that by publishing a key one cache TTL before signing with it.

A service that holds its keys itself (identity-api) passes `StaticKeySource` instead, so there is no HTTP call.

## Develop

```sh
cd packages/py-auth
pip install -e '.[dev]'
ruff check . && ruff format --check . && mypy && pytest
```

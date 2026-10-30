# Runbook: rotate the identity-api JWT signing key

identity-api signs admin tokens with an RS256 private key and publishes the public keys at `GET /.well-known/jwks.json` ([ADR 0009](../adr/0009-auth-model.md)). Other services verify tokens with the JWKS and cache it for **10 minutes** (`Cache-Control: max-age=600`); on an unknown `kid` they refetch at most once a minute.

Two numbers drive every wait below:

- **Cache TTL:** 10 minutes. Until then a service may still hold the old key set.
- **Token lifetime:** 15 minutes (`ACCESS_TOKEN_TTL_SECONDS`).

How keys are configured (see `services/identity-api/.env.example`):

- `JWT_KEYS_DIR`: a directory of `<kid>.pem` files, or `JWT_KEYS`: a JSON object `{"<kid>": "<PEM>"}`. Both can be used; a `kid` may appear only once.
- `JWT_SIGNING_KID`: the key that signs. Every other key is **published only**. A published-only key can be configured as a **public** PEM, so a retired private key does not have to be kept.
- Keys are read at startup. A change takes effect when the service restarts. With several instances, restart them one at a time (rolling) and check `/.well-known/jwks.json` on each.

`kid` convention: `YYYY-MM-DD-<6 hex>`, which is what `python -m identity_api.cli generate-key` produces.

## Normal rotation (every 90 days)

Nobody is signed out. Allow about 40 minutes in total.

Let `OLD` be the current signing `kid` and `NEW` the new one.

1. **Generate the new key** where your secrets are managed (not on a laptop for production):
   ```sh
   python -m identity_api.cli generate-key --dir <secure dir>
   ```
   It prints `NEW`. The private key is written with mode `0600`; never commit or paste it anywhere.
2. **Publish `NEW` without signing with it.** Add `NEW`'s private key to the secret store next to `OLD`, keep `JWT_SIGNING_KID=OLD`, and roll the identity-api instances.
3. **Check:** `curl -s $ISSUER/.well-known/jwks.json` lists both `OLD` and `NEW`, on every instance. New tokens still carry `kid` `OLD`.
4. **Wait at least 10 minutes** (one cache TTL), so every service has fetched a key set that contains `NEW`. Signing earlier would hand out tokens that a service with a cached key set cannot verify yet; it would then refetch (at most once a minute), but do not rely on that.
5. **Switch signing to `NEW`:** set `JWT_SIGNING_KID=NEW` and roll the instances. Check that a fresh login gives a token whose header has `kid` `NEW`, and that a service accepts it.
6. **Wait at least 25 minutes** (15 minutes token lifetime plus 10 minutes cache TTL) after the *last* instance started signing with `NEW`, so every token signed by `OLD` has expired.
7. **Retire `OLD`:** delete `OLD` from the secret store (or from `JWT_KEYS_DIR`/`JWT_KEYS`) and roll the instances. Check that the JWKS lists only `NEW`.
8. **Destroy `OLD`'s private key** everywhere it was stored, and note the rotation date. Schedule the next one in 90 days.

If something looks wrong between steps 2 and 5, undo the last change: no token has been invalidated yet.

## Emergency rotation (suspected key leak)

Do this at once; it ends every admin session. Admins sign in again afterwards.

1. **Generate a new key** (step 1 above) and note `NEW`.
2. **Replace the keys:** configure `NEW` as the only key, with `JWT_SIGNING_KID=NEW`. Do **not** keep `OLD`, not even as a public key. Roll all identity-api instances together, or restart them at once rather than one by one.
3. **Check** that the JWKS lists only `NEW` and that a fresh login works.
4. **Know the gap.** Services keep their cached key set for up to 10 minutes, so tokens signed with `OLD` can still verify for up to that long (and no longer than their own 15-minute expiry). To close it sooner, restart the services that verify admin tokens (or clear their JWKS cache) right after step 2.
5. **Revoke refresh tokens.** Refresh tokens are not signed, but they were issued under the leaked key's regime: revoke all refresh-token families in Postgres so nobody can refresh into a new session without signing in again. (The revoke-all command arrives with the refresh-token work in Phase 1; until then, truncate the refresh-token table by hand.)
6. **Find out how the key leaked** and fix that first. Review the logs for tokens with unexpected `sub`/`roles` between the leak and the rotation, using `jti` to trace them.
7. **Destroy `OLD`** everywhere and record the incident and the rotation time.

## Quick reference

| Situation | `JWT_SIGNING_KID` | JWKS contains |
|---|---|---|
| Steady state | `K1` | `K1` |
| Step 2 to 4: new key announced | `K1` | `K1`, `K2` |
| Step 5 to 6: new key signs | `K2` | `K1`, `K2` |
| After step 7 | `K2` | `K2` |
| Emergency | `K2` | `K2` |

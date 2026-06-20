# DJConnect API Handoff

## Current State

- Repository: `pcvantol/djconnect-api`.
- Runtime: Cloudflare Worker.
- Current release: `1.0.1`.
- Purpose: central APNs push relay for DJConnect Apple clients.
- Public API target: `https://api.djconnect.dev`.
- D1 database: `djconnect_api`.
- D1 binding: `DB`.
- Worker source: `src/`.
- D1 migrations: `migrations/`.

This repository is intended to be public/open-source. Treat all code, docs,
tests and fixtures as public material.

## Cross-Repo Source Of Truth

Do not copy these files into this repository:

- `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/PRODUCT_ROADMAP.md`

The Home Assistant integration remains the source of truth for client-facing HA
API contracts. This API repository owns only the central relay API surface under
`/v1/push/*`.

## Architecture

```text
Home Assistant DJConnect integration
  -> authenticated privacy-safe relay event
  -> DJConnect API Worker
  -> D1 registration lookup/audit
  -> APNs provider-token authenticated push
  -> iOS/macOS/watchOS client opens
  -> client syncs with its own Home Assistant instance
```

The APNs private key stays only in Cloudflare secrets/configuration. Home
Assistant, HACS integrations and clients must never receive the APNs provider
private key.

## Endpoint Contract

Public health:

- `GET /health`

Relay endpoints:

- `POST /v1/push/register`
- `POST /v1/push/unregister`
- `POST /v1/push/event`

All `/v1/push/*` endpoints require relay auth using `DJCONNECT_RELAY_SECRET`
through bearer auth or HMAC signature.

## Privacy Boundaries

The Worker must not log, store or relay:

- Raw prompts.
- Raw assistant responses.
- Full chat history.
- DJ Memory.
- Home Assistant tokens.
- Spotify tokens.
- APNs provider private key.
- Relay secret.
- Production user, device or install identifiers in tests/fixtures.

APNs payloads are generic wake/sync hints. Clients must always sync through
their own Home Assistant instance after opening, especially
`/api/djconnect/ask_dj/history`.

## Current Decisions

- D1 stores `apns_token_hash` for lookup/audit and `apns_token` as development
  relay storage. Replace this with encryption at rest before production use.
- APNs endpoint selection is per registration: sandbox or production.
- `BadDeviceToken`, `Unregistered` and HTTP 410 mark a registration
  disabled/invalid.
- Audit rows are intentionally minimal and do not contain prompts, responses,
  secrets or full history.
- Tests use example fixture values only.

## Validation Status For 1.0.0

Passed:

- `npx wrangler types`
- `npx tsc --noEmit`
- `npm test`
- `npx wrangler d1 migrations apply djconnect_api --local`
- Public repository secret scan

Blocked by external Cloudflare auth:

- Remote D1 migration returned account authorization error `7403`.
- Worker deploy returned Wrangler authentication error `10000`.

## Manual Cloudflare Work Still Required

Most of this can be automated with:

```sh
npm run provision:cloudflare -- --dry-run --all
```

After reviewing the dry-run, run selected steps with `--execute`.
Custom-domain automation works only after Cloudflare auth is fixed and
`CLOUDFLARE_ACCOUNT_ID` plus `CLOUDFLARE_API_TOKEN` are valid for the target
account.

1. Fix Cloudflare account/API token permissions for the account that owns D1
   database `476a564f-08b2-4966-83b0-1221e2a4d063`.
2. Set Cloudflare secrets:
   - `APNS_PRIVATE_KEY`
   - `DJCONNECT_RELAY_SECRET`

   Automated form:

   ```sh
   DJCONNECT_RELAY_SECRET_VALUE='replace-with-long-random-secret' \
     scripts/provision_cloudflare.sh --execute --set-secrets \
     --apns-private-key-file /secure/path/to/key.p8
   ```
3. Apply remote D1 migration:

   ```sh
   npx wrangler d1 migrations apply djconnect_api --remote
   ```

4. Deploy the Worker:

   ```sh
   npm run deploy
   ```

   Automated form:

   ```sh
   scripts/provision_cloudflare.sh --execute --migrate --deploy
   ```

5. Route `https://api.djconnect.dev` to the deployed Worker in Cloudflare.
6. Smoke test:

   ```sh
   curl https://api.djconnect.dev/health
   ```

   Automated form:

   ```sh
   scripts/provision_cloudflare.sh --execute --custom-domain --smoke-test
   ```

Expected response:

```json
{"ok":true,"service":"djconnect-api"}
```

Do not print or commit the APNs `.p8` key, relay secret, Cloudflare token or
any real APNs device token while completing these steps.

## Release Checklist

Before every release:

- Review canonical cross-repo docs in the Home Assistant integration repo.
- Update `CHANGELOG.md`.
- Update docs when behavior, setup, security posture or release flow changes.
- Run tests/typecheck/local migration validation.
- Run the public repository secret scan.
- Attempt remote D1 migration and Worker deploy when Cloudflare credentials are
  available.
- Use `CHANGELOG.md` as GitHub Release body.
- Run `./cleanup_old_releases.sh --keep 1` dry-run before publishing, then
  `./cleanup_old_releases.sh --keep 1 --execute` by default after the new
  GitHub Release is published and verified.

## Next Actions

- Fix Cloudflare token/account permissions for remote D1 migrations and Worker
  deploy.
- Configure required Cloudflare secrets outside the repository.
- Route and smoke test `https://api.djconnect.dev`.
- Replace plain `apns_token` storage with encrypted-at-rest token storage.
- Add per-install relay tokens when HA integration support is ready.
- Add deployment smoke checks for `https://api.djconnect.dev/health`.

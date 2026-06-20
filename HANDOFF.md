# DJConnect API Handoff

## Current State

- Repository: `pcvantol/djconnect-api`.
- Runtime: Cloudflare Worker.
- Current release: `1.0.6`.
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

- `POST /v1/install/token`
- `POST /v1/install/rotate`
- `POST /v1/push/register`
- `POST /v1/push/unregister`
- `POST /v1/push/event`

Admin endpoints:

- `GET /v1/admin/registrations`

`POST /v1/install/bootstrap-proof` requires bootstrap/operator auth using
`DJCONNECT_RELAY_SECRET` through bearer auth or HMAC signature and returns a
short-lived one-time `djcboot_...` proof for an existing pairing context.
Public Home Assistant/HACS installations must not receive that bootstrap
secret.

`POST /v1/install/token` is proof-only. It consumes a valid `djcboot_...` proof
bound to `ha_install_id`, `client_type` and `device_id`, then returns a
per-install `djci_...` token. Proofs are stored hashed and consumption is
rate-limited by hashed IP/install/device keys in D1.

`/v1/push/*` and `/v1/install/rotate` require a per-install `djci_...` token
scoped to the request `ha_install_id`.

`GET /v1/admin/registrations` requires bootstrap/operator auth, rejects
per-install tokens and returns only privacy-safe metadata for the admin website.

The Home Assistant/HACS side now handles per-install token provisioning
automatically during setup. It creates/persists `ha_install_id`, obtains a
`djci_...` token, stores it in Home Assistant config entry options and uses it
as bearer auth for central calls. Manual token/API URL controls are support-only
override/rotation tools, not the normal user flow.
The admin website must use this endpoint rather than reading D1 directly.

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
- Raw production install IDs or device IDs in admin responses.

APNs payloads are generic wake/sync hints. Clients must always sync through
their own Home Assistant instance after opening, especially
`/api/djconnect/ask_dj/history`.

## Current Decisions

- D1 stores `apns_token_hash` for lookup/audit and encrypted APNs token
  material for relay delivery. The nullable `apns_token` column remains only as
  a legacy migration fallback for old rows.
- `OPERATOR_RUNBOOK.md` documents the APNs token encryption key rotation and
  backfill procedure. The current Worker runtime still uses one active
  `APNS_TOKEN_ENCRYPTION_KEY`; planned zero-downtime rotation requires a
  temporary dual-key/backfill implementation before replacing the secret.
- APNs endpoint selection is per registration: sandbox or production.
- `BadDeviceToken`, `Unregistered` and HTTP 410 mark a registration
  disabled/invalid.
- Audit rows are intentionally minimal and do not contain prompts, responses,
  secrets or full history.
- Per-install relay tokens are stored only as SHA-256 hashes in D1.
- Tests use example fixture values only.

## Historical Validation Notes

Initial `v1.0.0` validation passed:

- `npx wrangler types`
- `npx tsc --noEmit`
- `npm test`
- `npx wrangler d1 migrations apply djconnect_api --local`
- Public repository secret scan

Initial `v1.0.0` release validation was previously blocked by external
Cloudflare auth:

- Remote D1 migration returned account authorization error `7403`.
- Worker deploy returned Wrangler authentication error `10000`.

These blockers are resolved as of `v1.0.2`; CI/CD now deploys `main`
successfully.

## Cloudflare And CI/CD Status

Cloudflare production setup is active:

- `APNS_PRIVATE_KEY` is installed as a Cloudflare Worker secret.
- `DJCONNECT_RELAY_SECRET` is installed as a Cloudflare Worker secret.
- `APNS_TOKEN_ENCRYPTION_KEY` must be installed as a Cloudflare Worker secret
  before encrypted APNs registrations are accepted.
- `DJCONNECT_SMOKE_TEST_MODE=enabled` is installed as a Cloudflare Worker
  secret so CI can run proof -> token -> register -> event smoke coverage using
  only `example-...` APNs tokens without contacting APNs.
- Remote D1 contains `install_tokens`, `registrations` and `relay_events`.
- Worker deploy succeeded.
- `https://api.djconnect.dev/health` returns `{"ok":true,"service":"djconnect-api"}`.

GitHub Actions CI/CD is configured in `.github/workflows/ci-cd.yml`:

- `Validate` runs on pull requests and pushes to `main`.
- `Deploy` runs on pushes to `main` after validation.
- GitHub secret `CLOUDFLARE_API_TOKEN` is configured with Workers deploy, D1
  migration and Workers Routes edit permissions for `djconnect.dev`.
- The latest `main` CI/CD run is green.

Manual/operator provisioning remains available with:

```sh
npm run provision:cloudflare -- --dry-run --all
```

Expected response:

```json
{"ok":true,"service":"djconnect-api"}
```

Do not print or commit the APNs `.p8` key, relay secret, Cloudflare token or
any real APNs device token while operating or debugging the deployment.

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
  GitHub Release is published and verified. This also removes old completed
  GitHub Actions workflow runs unless `--skip-workflow-runs` is passed.

## Next Actions

- Validate the encrypted APNs token migration in remote D1 after deployment.
- Build a temporary dual-key/backfill implementation before the first planned
  `APNS_TOKEN_ENCRYPTION_KEY` rotation.
- Keep GitHub Actions `DJCONNECT_RELAY_SECRET` configured so the staging-safe
  E2E smoke test continues to run.

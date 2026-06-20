# Changelog

## 1.0.3 - 2026-06-20

- Documented that HACS-side per-install token provisioning is now automatic:
  the integration persists `ha_install_id`, obtains/stores a `djci_...` token
  during setup and uses support/options UI only for override or rotation.
- Added proof-based HACS bootstrap:
  - `POST /v1/install/bootstrap-proof` issues short-lived one-time
    `djcboot_...` proofs through operator/admin auth.
  - `POST /v1/install/token` consumes valid proofs and no longer accepts
    operator auth as a fallback.
  - Proofs are stored hashed, bound to install/client/device context and
    consumed behind D1 rate limits.
- Added APNs token encryption at rest for D1 registrations:
  - New registrations store encrypted token material instead of raw
    `apns_token` values.
  - Added `APNS_TOKEN_ENCRYPTION_KEY` as a Cloudflare Worker secret.
  - Added a D1 migration that rebuilds `registrations` so `apns_token` is
    nullable and encrypted columns are available.
  - Kept legacy nullable `apns_token` fallback for old rows during migration.
- Extended provisioning docs and script support for
  `APNS_TOKEN_ENCRYPTION_KEY`.
- Added `GET /v1/admin/registrations` for the DJConnect admin website:
  - Requires bootstrap/operator auth and rejects per-install `djci_...` tokens.
  - Supports pagination and privacy-safe filters for client type, APNs
    environment, disabled/invalid status and install ID.
  - Returns hashed install/device identifiers and operational registration
    metadata only.
  - Never returns raw APNs tokens, encrypted token material, nonces or secrets.

## 1.0.2 - 2026-06-20

- Added the `api.djconnect.dev` custom-domain route to `wrangler.jsonc`.
- Added GitHub Actions CI/CD:
  - `Validate` runs install, typecheck, Wrangler deploy dry-run, tests and a
    public-repo secret-pattern scan.
  - `Deploy` runs remote D1 migrations, Worker deploy and `/health` smoke test
    on pushes to `main`.
- Updated CI actions to `actions/checkout@v5` and `actions/setup-node@v5`.
- Updated test dependencies for the Dependabot security batch:
  `@cloudflare/vitest-pool-workers` to `0.16.18`, `vitest` to `4.1.9` and
  transitive `esbuild` to `0.28.1`.
- Updated `vitest.config.mts` to the Vitest 4 Cloudflare Workers plugin API.
- Extended release cleanup so `cleanup_old_releases.sh` removes old completed
  GitHub Actions workflow runs in addition to old releases/tags.
- Documented Cloudflare API token permissions for D1, Workers deploy and
  Workers Routes on `djconnect.dev`.
- Validated production Cloudflare setup:
  - Remote D1 contains `install_tokens`, `registrations` and `relay_events`.
  - Worker deploy succeeds through CI/CD.
  - `https://api.djconnect.dev/health` returns
    `{"ok":true,"service":"djconnect-api"}`.

## 1.0.1 - 2026-06-20

- Added production-level project documentation: contributing guide, code of
  conduct, development environment, handoff, issue backlog, TODO backlog,
  technical design decisions, third-party notices and MIT license.
- Added `cleanup_old_releases.sh` for dry-run-first GitHub release/tag cleanup.
- Expanded `AGENTS.md` and `README.md` with public repository and release
  hygiene guidance.
- Configured GitHub repository hygiene outside the codebase: public metadata,
  squash-only merge strategy, automatic head-branch deletion, security scanning,
  push protection, Dependabot security updates, private vulnerability reporting
  and protected `main` with pull-request review requirements.
- Documented release cleanup as default behavior: after a new release is
  published and verified, old GitHub releases/tags are removed with
  `./cleanup_old_releases.sh --keep 1 --execute` unless intentionally retained.
- Expanded Cloudflare operator documentation for required account permissions,
  APNs `.p8` secret handling, remote D1 migration, Worker deploy,
  `api.djconnect.dev` routing and `/health` smoke testing.
- Added `scripts/provision_cloudflare.sh`, a dry-run-first provisioning helper
  for Cloudflare secrets, remote D1 migration, Worker deploy, custom domain
  setup and `/health` smoke testing without printing secret values.
- Hardened provisioning docs and script behavior with explicit `--dry-run`,
  Cloudflare API token verification before execute-mode changes and a note that
  custom-domain automation requires fixed Cloudflare auth/account permissions.
- Added production-ready per-install relay tokens:
  - `POST /v1/install/token` issues one-time-visible `djci_...` tokens through
    trusted bootstrap auth.
  - `POST /v1/install/rotate` rotates a single installation token.
  - `/v1/push/register`, `/v1/push/unregister` and `/v1/push/event` now require
    a per-install token scoped to the request `ha_install_id`.
  - D1 stores install tokens only as SHA-256 hashes.

## 1.0.0 - 2026-06-20

Initial public DJConnect API backend release.

- Added Cloudflare Worker endpoints for `GET /health`, `POST /v1/push/register`, `POST /v1/push/unregister` and `POST /v1/push/event`.
- Added D1 schema and migration for Apple push registrations and minimal relay event audit rows.
- Added relay auth using `DJCONNECT_RELAY_SECRET` via bearer token or HMAC signature.
- Added APNs provider-token authentication with ES256 JWT signing and sandbox/production endpoint selection.
- Added invalid-token handling for `BadDeviceToken`, `Unregistered` and HTTP 410 responses.
- Added privacy-safe APNs payload generation with generic wake/sync notifications only.
- Added public API, security and setup documentation.
- Added unit tests for auth, D1 register/unregister writes, APNs payload privacy, invalid token handling and endpoint selection.

Validation:

- `npx wrangler types`
- `npx tsc --noEmit`
- `npm test`
- `npx wrangler d1 migrations apply djconnect_api --local`
- Public repository secret scan for APNs keys, relay secrets, bearer tokens, Spotify/HA tokens and production identifiers

Known release notes:

- Remote D1 migration was attempted during release validation but Cloudflare returned account authorization error `7403`.
- Worker deploy was attempted during release validation but Wrangler returned authentication error `10000` for the configured API token.
- Remote D1 migration and Cloudflare deploy require the correct Cloudflare account authorization and secrets to be configured outside the repository.
- APNs token storage in `v1.0.0` was intentionally documented as
  development-ready plain storage and had to be replaced by encrypted-at-rest
  storage before broader production use.

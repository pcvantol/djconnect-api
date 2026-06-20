# Changelog

## Unreleased

- Added production-level project documentation: contributing guide, code of
  conduct, development environment, handoff, issue backlog, TODO backlog,
  technical design decisions, third-party notices and MIT license.
- Added `cleanup_old_releases.sh` for dry-run-first GitHub release/tag cleanup.
- Expanded `AGENTS.md` and `README.md` with public repository and release
  hygiene guidance.

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
- APNs token storage is intentionally documented as development-ready plain storage and must be replaced by encrypted-at-rest storage before production use.

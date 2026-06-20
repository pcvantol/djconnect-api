# DJConnect API Technical Design Decisions

This document records code-level design decisions, implementation patterns,
runtime dependencies and public-repo constraints for the DJConnect API Worker.

Sources used for this document:

- Local source tree under `src/`.
- D1 migration in `migrations/0001_initial.sql`.
- Worker config in `wrangler.jsonc`.
- Tests under `test/`.
- Cross-repo contracts in `/Users/pcvantol/Documents/GitHub/djconnect`.

## Scope

This repository contains the MIT-licensed central Cloudflare Worker API for
DJConnect APNs push relay.

The Home Assistant integration remains the leading client-facing API owner.
This Worker centralizes APNs provider credentials and relays privacy-safe
wake/sync events to Apple clients.

## Runtime Design Decisions

### Cloudflare Worker As The Trust Boundary

Pattern:

- The APNs provider private key is only read from Cloudflare secrets/config.
- Home Assistant/HACS integrations call authenticated relay endpoints.
- Apple clients receive generic APNs payloads and then sync with their own Home
  Assistant instance.

Primary source files:

- `src/index.ts`
- `src/auth.ts`
- `src/apns.ts`

Why:

- Home Assistant users and HACS integrations never need APNs provider
  credentials.
- APNs delivery can be operated centrally while keeping user data in each Home
  Assistant instance.

### Explicit Route Handler Without Framework

Pattern:

- `src/index.ts` routes `GET /health` and `POST /v1/push/*` directly.
- Request validation is kept close to each endpoint.
- `HttpError` maps controlled failures to JSON error responses.

Why:

- The API surface is intentionally small.
- Avoids unnecessary framework dependencies in an edge Worker.
- Keeps tests focused on the actual Cloudflare runtime behavior.

### Per-Install Relay Auth With Bootstrap Secret

Pattern:

- `DJCONNECT_RELAY_SECRET` is a bootstrap/operator secret for trusted
  `POST /v1/install/bootstrap-proof` calls only.
- HMAC bootstrap auth signs `timestamp + "." + raw_body`; timestamp skew is
  limited to five minutes.
- Bootstrap proofs use `djcboot_...`, are stored only as SHA-256 hashes, are
  one-time use, expire quickly and are bound to install/client/device context.
- Public HACS installs receive a per-install `djci_...` bearer token through
  automatic setup/provisioning. The normal `/v1/install/token` path consumes a
  short-lived one-time `djcboot_...` proof and does not accept the operator
  secret as a fallback. Users should not have to paste this token in the normal
  onboarding path.
- Push/register/event calls require a per-install token scoped to the same
  `ha_install_id`.
- Install tokens are stored only as SHA-256 hashes in D1.
- Proof consumption is D1 rate-limited using hashed IP/install/device keys.
- Comparisons use hashed timing-safe equality.

Primary source files:

- `src/auth.ts`
- `src/crypto.ts`

Why:

- Avoids shipping a global shared secret in open-source HACS code.
- Keeps the user-facing flow quiet: setup provisions the token under the hood,
  while options/support UI can inspect, replace or rotate it when needed.
- Allows per-install rotation/revocation without affecting other installs.
- Keeps APNs provider credentials server-side while still allowing privacy-safe
  HA wake/sync events.

### D1 As Registration And Audit Store

Pattern:

- `registrations` stores install/user/device/client metadata plus APNs token
  routing fields.
- `install_tokens` stores per-install token hashes and rotation metadata.
- `relay_events` stores minimal counts only.
- Audit rows intentionally exclude prompts, responses, history, memory and
  secrets.

Primary source files:

- `migrations/0001_initial.sql`
- `src/repository.ts`

Why:

- D1 is a good fit for small relational registration lookup and audit.
- The database schema can be public because it contains no credentials.

Security posture:

- New APNs registrations store encrypted token material in D1 using AES-GCM and
  the Cloudflare Worker secret `APNS_TOKEN_ENCRYPTION_KEY`.
- `apns_token_hash` remains available for lookup/audit without revealing the
  raw token.
- The nullable `apns_token` column is retained only as a legacy migration
  fallback and should stay empty for new rows.

### APNs Provider Token Auth

Pattern:

- Provider token JWT uses ES256 with `APNS_TEAM_ID`, `APNS_KEY_ID` and
  `APNS_PRIVATE_KEY`.
- Registration environment selects Apple sandbox or production endpoint.
- Per-client topic comes from `APNS_TOPIC_IOS`, `APNS_TOPIC_MACOS` or
  `APNS_TOPIC_WATCHOS`.

Primary source file:

- `src/apns.ts`

Why:

- Provider-token auth is the APNs model that keeps one server-side private key.
- Topic/environment are explicit and testable.

### Generic APNs Payloads

Pattern:

- `ask_dj_response` sends "Ask DJ heeft geantwoord."
- `ask_dj_confirm` sends "Ask DJ wacht op je keuze."
- Payloads include only sync hints such as `event_type`, `history_revision`,
  `client_message_id` and `open_target`.

Why:

- Push is an attention/wake signal only.
- Clients must sync with their own Home Assistant instance after opening.
- Raw prompts, raw assistant responses and full history stay out of APNs.

### Invalid Token Handling

Pattern:

- APNs `BadDeviceToken`, `Unregistered` and HTTP 410 disable and invalidate the
  registration.
- Other APNs errors are recorded as `last_error_code` without disabling unless
  they match invalid-token semantics.

Primary source files:

- `src/apns.ts`
- `src/index.ts`
- `src/repository.ts`

Why:

- Invalid tokens should stop repeated delivery attempts.
- Transient APNs failures should not remove registrations prematurely.

## Testing Strategy

Tests use `@cloudflare/vitest-pool-workers` and D1 in the Worker test runtime.
The suite covers:

- Auth required.
- Privacy-safe APNs payloads.
- Register/unregister D1 writes.
- Invalid APNs token disabling.
- Sandbox/production APNs endpoint selection.

Tests must use example fixtures only, never production identifiers or real
tokens.

## Dependency Inventory

Declared project dependencies:

- `wrangler`: Cloudflare Workers CLI for development, type generation and
  deploy.
- `typescript`: Type checking.
- `vitest`: Test runner.
- `@cloudflare/vitest-pool-workers`: Cloudflare Worker runtime test pool.
- `@types/node`: Node.js type helpers needed by the local toolchain.

Runtime platform dependencies:

- Cloudflare Workers runtime.
- Cloudflare D1.
- Web Crypto APIs.
- APNs HTTP/2 provider API.

## Public Repository Constraints

This repository may be public. Never commit:

- APNs `.p8` private keys.
- `DJCONNECT_RELAY_SECRET`.
- Real APNs device tokens.
- Home Assistant tokens.
- Spotify tokens.
- Cloudflare API tokens.
- Production user, install or device identifiers.
- Logs with request bodies containing user data or tokens.

Use only example values in docs and tests.

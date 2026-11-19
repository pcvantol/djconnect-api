# DJConnect API Issues Backlog

## Open / Needs Validation

### Operator token revocation

- Status: open.
- Area: HA -> API auth operations.
- Symptom: Per-install token rotation exists, but there is no operator-only
  revoke/disable endpoint for a compromised install token.
- Current mitigation: Tokens are stored only as SHA-256 hashes and scoped to one
  `ha_install_id`.
- Next action: Add an authenticated operator endpoint or maintenance script to
  disable install tokens by install id/token id.

### Production APNs delivery validation

- Status: field validation.
- Area: APNs delivery.
- Symptom: Provider-token signing and endpoint selection are tested with mocked
  APNs responses, not real Apple delivery from production devices.
- Current mitigation: Unit tests cover sandbox/production URL selection,
  payload privacy and invalid-token handling. Cloudflare secrets are installed.
- Next action: Validate real sandbox and production APNs delivery after Apple
  clients send live registrations.

## Resolved

### HACS pairing and install-token provisioning

- Status: implemented in the Home Assistant/HACS integration.
- Resolution: The integration provisions itself automatically during setup:
  it creates/persists a stable `ha_install_id`, obtains a per-install
  `djci_...` token, stores that token in Home Assistant config entry options
  and uses it as `Authorization: Bearer <djci_token>` for central API calls.
- The normal user flow does not require manually pasting a token. API URL/token
  controls are support/override tools for inspection, replacement and rotation.
- Security boundary: HACS/client code must not contain `DJCONNECT_RELAY_SECRET`,
  APNs private key material, Cloudflare tokens or any global project secret.

### APNs token encryption at rest

- Status: implemented after `v1.0.2`.
- Resolution: New APNs registrations store encrypted token material in D1 using
  AES-GCM and the Cloudflare Worker secret `APNS_TOKEN_ENCRYPTION_KEY`.
  `apns_token_hash` remains for lookup/audit. The nullable `apns_token` column
  is retained only as a legacy migration fallback.
- Follow-up: Validate the remote D1 migration and document any future
  key-rotation/backfill procedure.

### Cloudflare remote authorization

- Status: resolved in `v1.0.2`.
- Resolution: `CLOUDFLARE_API_TOKEN` now has D1 migration, Workers deploy,
  Workers Routes edit and Zone read permissions. The explicit production
  deployment workflow can deploy a qualified internal-release candidate.

### api.djconnect.dev routing

- Status: resolved in `v1.0.2`.
- Resolution: `wrangler.jsonc` contains the `api.djconnect.dev` custom-domain
  route and `https://api.djconnect.dev/health` returns
  `{"ok":true,"service":"djconnect-api"}`.

### Per-install relay credentials

- Status: implemented in `v1.0.1`.
- Resolution: `POST /v1/install/token` issues per-install `djci_...` tokens,
  `POST /v1/install/rotate` rotates them and `/v1/push/*` endpoints require a
  token scoped to the request `ha_install_id`.

## Regression Watchlist

- Register/event endpoints must never allow anonymous calls.
- `DJCONNECT_RELAY_SECRET` must never be shipped in HACS/client code.
- APNs payloads must never contain raw prompts, raw assistant responses, full
  chat history, memory, Home Assistant tokens or Spotify tokens.
- Tests must use example values only.
- `.p8`, `.env`, `.dev.vars` and Wrangler state must stay ignored.
- `worker-configuration.d.ts` must be regenerated after binding/config changes.
- D1 migrations must remain public-safe and avoid secrets.
- Remote deploy errors must not be worked around by committing credentials.

# DJConnect API Issues Backlog

## Open / Needs Validation

### APNs token encryption at rest

- Status: open before broader production rollout.
- Area: D1 storage/security.
- Symptom: `apns_token` is stored in plain form so the relay can send APNs
  pushes.
- Current mitigation: `apns_token_hash` is used for lookup/audit; docs call out
  the plain token storage explicitly; request and audit logs must stay redacted.
- Next action: Replace plain storage with encrypted-at-rest storage or another
  protected token handling strategy.

### HACS pairing and install-token provisioning

- Status: open.
- Area: Home Assistant integration onboarding.
- Symptom: The central API has per-install `djci_...` tokens, but the
  user-facing pairing/provisioning flow for HACS still needs to be implemented.
- Current mitigation: `DJCONNECT_RELAY_SECRET` is kept as an operator/bootstrap
  secret only; HACS/client code must never contain it.
- Next action: Build the HACS-side token storage, rotation and privacy-safe
  event relay flow.

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

### Cloudflare remote authorization

- Status: resolved in `v1.0.2`.
- Resolution: `CLOUDFLARE_API_TOKEN` now has D1 migration, Workers deploy,
  Workers Routes edit and Zone read permissions. GitHub Actions CI/CD deploys
  `main` successfully.

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

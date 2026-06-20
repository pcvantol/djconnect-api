# DJConnect API Issues Backlog

## Open / Needs Validation

### Cloudflare remote authorization

- Status: open.
- Area: release/deploy.
- Symptom: Remote D1 migration returned Cloudflare account authorization error
  `7403`; Worker deploy returned Wrangler authentication error `10000`.
- Current mitigation: Local D1 migration validation passes; release notes record
  skipped remote steps.
- Next action: Fix Cloudflare API token/account permissions, then rerun remote
  migration and deploy.

### APNs token encryption at rest

- Status: open before production.
- Area: D1 storage/security.
- Symptom: `apns_token` is stored in plain form so development relay can send
  APNs pushes.
- Current mitigation: Docs call this out explicitly; token hash is used for
  lookup/audit.
- Next action: Replace plain storage with encrypted-at-rest storage or another
  protected token handling strategy.

### Per-install relay credentials

- Status: planned.
- Area: HA -> API auth.
- Symptom: Initial relay auth uses a shared secret or HMAC.
- Current mitigation: All relay endpoints require auth and use timing-safe
  comparison.
- Next action: Add per-install token issuance/rotation when the Home Assistant
  integration is ready.

### Production APNs validation

- Status: field validation.
- Area: APNs delivery.
- Symptom: Provider-token signing and endpoint selection are tested with mocked
  APNs responses, not real Apple delivery.
- Current mitigation: Unit tests cover sandbox/production URL selection and
  invalid-token handling.
- Next action: Validate real sandbox and production APNs delivery after
  Cloudflare secrets are configured.

### api.djconnect.dev routing

- Status: open.
- Area: DNS/routing.
- Symptom: Worker target domain is documented but deployment/routing was not
  completed due to Cloudflare auth errors.
- Current mitigation: Local tests and config are ready.
- Next action: Deploy Worker and route `api.djconnect.dev` after Cloudflare
  permissions are fixed.

## Regression Watchlist

- Register/event endpoints must never allow anonymous calls.
- APNs payloads must never contain raw prompts, raw assistant responses, full
  chat history, memory, Home Assistant tokens or Spotify tokens.
- Tests must use example values only.
- `.p8`, `.env`, `.dev.vars` and Wrangler state must stay ignored.
- `worker-configuration.d.ts` must be regenerated after binding/config changes.
- D1 migrations must remain public-safe and avoid secrets.
- Remote deploy errors must not be worked around by committing credentials.

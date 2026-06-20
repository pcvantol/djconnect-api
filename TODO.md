# DJConnect API TODO Backlog

## Production Hardening

- Keep `scripts/provision_cloudflare.sh --dry-run --all` as the operator
  preflight before manual `--execute` provisioning runs.
- Replace plain `apns_token` D1 storage with encrypted-at-rest storage.
- Add an operator-only disable/revoke endpoint for compromised per-install
  tokens.
- Add structured redacted logging helpers if more observability is needed.
- Re-run the public repository secret scan before every release.
- Confirm no request-body logging is enabled in Cloudflare observability/tail
  workflows.

## Security / Privacy

- Keep `DJCONNECT_RELAY_SECRET` as an operator/bootstrap secret only; never ship
  it in HACS/client code.
- Keep per-install `djci_...` tokens scoped to one `ha_install_id`.
- Keep tests and fixtures on example values only.

## API / Contracts

- Keep `/v1/push/*` aligned with the Home Assistant integration relay contract
  when that integration starts calling this central API.
- Keep `API_CONTRACT.md` aligned with
  `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`.
- Add a compatibility note if HA integration versions require a specific API
  release line.
- Design the user-facing pairing/provisioning flow that delivers a per-install
  token to HACS without embedding global secrets.

## Testing

- Add tests for HMAC-auth success and timestamp rejection.
- Add tests for multiple client types and per-client topic selection.
- Add tests for optional `ha_user_hash` filtering.
- Add tests for audit row counts after mixed APNs success/failure.
- Add integration smoke tests beyond `/health` once a staging install-token
  provisioning flow exists.

## Documentation

- Keep `README.md`, `API_CONTRACT.md`, `SECURITY.md`, `CHANGELOG.md`,
  `HANDOFF.md`, `ISSUES.md`, `TECHNICAL_DESIGN_DECISIONS.md`,
  `DEVELOPMENT_ENVIRONMENT.md`, `THIRD_PARTY_NOTICES.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `CHAT_BOOTSTRAP.md` and `AGENTS.md` current.
- Keep cross-repo sync prompts and product roadmap only in
  `/Users/pcvantol/Documents/GitHub/djconnect`.

## Release Workflow

- Run `npx wrangler types`.
- Run `npx tsc --noEmit`.
- Run `npm test`.
- Run `npx wrangler d1 migrations apply djconnect_api --local`.
- Attempt remote migration/deploy when credentials are available.
- Use `CHANGELOG.md` for GitHub Release notes.
- Run `./cleanup_old_releases.sh --keep 1` as a dry-run before publishing.
- Run `./cleanup_old_releases.sh --keep 1 --execute` by default after the new
  GitHub Release is published and verified; this also removes old completed
  GitHub Actions workflow runs.

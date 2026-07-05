# DJConnect API TODO Backlog

## Production Hardening

- Keep `scripts/provision_cloudflare.sh --dry-run --all` as the operator
  preflight before manual `--execute` provisioning runs.
- Build temporary dual-key/backfill tooling before the first planned
  `APNS_TOKEN_ENCRYPTION_KEY` rotation.
- Add structured redacted logging helpers if more observability is needed.
- Re-run the public repository secret scan before every release.
- Confirm no request-body logging is enabled in Cloudflare observability/tail
  workflows.

## Security / Privacy

- Keep `DJCONNECT_RELAY_SECRET` as an operator/bootstrap secret only; never ship
  it in HACS/client code.
- Keep per-install `djci_...` tokens scoped to one `ha_install_id`.
- Keep `APNS_TOKEN_ENCRYPTION_KEY` only in Cloudflare Worker secrets and never
  in GitHub Actions, local env files or fixtures.
- Keep tests and fixtures on example values only.

## API / Contracts

- Keep `/v1/push/*` aligned with the Home Assistant integration relay contract
  as the integration uses this central API.
- Keep `API_CONTRACT.md` aligned with
  `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`.
- Add a compatibility note if HA integration versions require a specific API
  release line.
- Keep the HACS token provisioning docs aligned with the implemented automatic
  setup flow. Manual token/API URL controls are support-only, not the normal
  onboarding path.

## Testing

- Enable the staging-safe E2E smoke test in CI by setting GitHub Actions secret
  `DJCONNECT_RELAY_SECRET` to the same value as the Cloudflare Worker secret.
  `DJCONNECT_SMOKE_TEST_MODE=enabled` is already required on the Worker side.

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
- Review translations in all five supported languages: `en`, `nl`, `de`, `fr`
  and `es`.
- Use `CHANGELOG.md` for GitHub Release notes.
- Run `./cleanup_old_releases.sh --keep 1` as a dry-run before publishing.
- Run `./cleanup_old_releases.sh --keep 1 --execute` by default after the new
  GitHub Release is published and verified; this also removes old completed
  GitHub Actions workflow runs.

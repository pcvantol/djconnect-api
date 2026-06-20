# DJConnect API TODO Backlog

## Immediate Validation

- Fix Cloudflare account/API token permissions for remote D1 migration and
  Worker deploy. Required permissions include Workers Scripts deploy/edit and
  D1 edit/query/migration access for database
  `476a564f-08b2-4966-83b0-1221e2a4d063`.
- Run `npx wrangler d1 migrations apply djconnect_api --remote`.
- Run `npm run deploy`.
- Configure `api.djconnect.dev` routing to the deployed Worker.
- Set Cloudflare secrets outside the repository:
  - `APNS_PRIVATE_KEY`
  - `DJCONNECT_RELAY_SECRET`
- For `APNS_PRIVATE_KEY`, paste the full Apple `.p8` file contents into
  `npx wrangler secret put APNS_PRIVATE_KEY` when prompted. Do not print or
  commit it.
- Smoke test `GET https://api.djconnect.dev/health`.

## Security / Privacy

- Replace plain `apns_token` D1 storage with encrypted-at-rest storage.
- Add per-install relay tokens with rotation/revocation support.
- Add structured redacted logging helpers if more observability is needed.
- Re-run the public repository secret scan before every release.
- Confirm no request-body logging is enabled in Cloudflare observability/tail
  workflows.

## API / Contracts

- Keep `/v1/push/*` aligned with the Home Assistant integration relay contract
  when that integration starts calling this central API.
- Keep `API_CONTRACT.md` aligned with
  `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`.
- Add a compatibility note if HA integration versions require a specific API
  release line.
- Add per-install token endpoints or provisioning flow when designed.

## Testing

- Add tests for HMAC-auth success and timestamp rejection.
- Add tests for multiple client types and per-client topic selection.
- Add tests for optional `ha_user_hash` filtering.
- Add tests for audit row counts after mixed APNs success/failure.
- Add integration smoke tests after a deployed Worker URL exists.

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
  GitHub Release is published and verified.

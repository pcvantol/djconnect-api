# DJConnect API

Central Cloudflare Workers backend for DJConnect APNs push relay.

The Worker keeps the APNs `.p8` key server-side as a Cloudflare secret. Home Assistant and HACS integrations call this API with privacy-safe wake/sync events and never receive APNs provider credentials.

Current release: `1.0.2`.

## Cloudflare Setup

Cloudflare setup is intentionally manual for production credentials. Do not
store APNs keys, relay secrets or Cloudflare tokens in this repository.

Most Cloudflare setup can also be automated with the safe provisioning script.
It is dry-run by default, also accepts explicit `--dry-run`, and never prints
secret values:

```sh
npm run provision:cloudflare -- --dry-run --all
```

Run selected actions with `--execute` only after reviewing the dry-run:

```sh
npm run provision:cloudflare -- --execute --migrate --deploy --custom-domain --smoke-test
```

To set secrets through the script, pass the APNs `.p8` file path as an argument
and the relay secret through an environment variable. The values are not echoed:

```sh
DJCONNECT_RELAY_SECRET_VALUE='replace-with-long-random-secret' \
APNS_TOKEN_ENCRYPTION_KEY_VALUE="$(openssl rand -base64 32)" \
  npm run provision:cloudflare -- --execute --set-secrets \
  --apns-private-key-file /secure/path/to/key.p8
```

For custom domain setup through the Cloudflare API, set:

```sh
export CLOUDFLARE_ACCOUNT_ID='replace-with-account-id'
export CLOUDFLARE_API_TOKEN='replace-with-api-token'
```

The script configures `api.djconnect.dev` for Worker service `djconnect-api` by
default. The production Worker is currently deployed and routed to
`https://api.djconnect.dev`.

### 1. Confirm Wrangler Account Permissions

Wrangler currently uses the active Cloudflare login or `CLOUDFLARE_API_TOKEN`.
The token/account must be authorized for:

- Workers Scripts edit/deploy.
- D1 database edit/query/migrations.
- Workers Routes edit for the `djconnect.dev` zone because `wrangler.jsonc`
  manages `api.djconnect.dev` as a custom domain route.
- Zone read for the `djconnect.dev` zone.
- Account access for the account that owns D1 database
  `476a564f-08b2-4966-83b0-1221e2a4d063`.

The production GitHub Actions secret `CLOUDFLARE_API_TOKEN` has these
permissions configured. If deploys fail with Cloudflare authentication errors,
verify the same permission set before rotating the token.

The D1 database already exists:

- `database_name`: `djconnect_api`
- `database_id`: `476a564f-08b2-4966-83b0-1221e2a4d063`
- binding: `DB`

### 2. Validate D1 Locally

Apply migrations locally:

```sh
npx wrangler d1 migrations apply djconnect_api --local
```

### 3. Set Secrets

Set required secrets through Cloudflare only:

```sh
npx wrangler secret put APNS_PRIVATE_KEY
npx wrangler secret put DJCONNECT_RELAY_SECRET
npx wrangler secret put APNS_TOKEN_ENCRYPTION_KEY
```

For `APNS_PRIVATE_KEY`, paste the full contents of the Apple `.p8` key into the
Wrangler prompt. Do not document local key filenames or paths, print the key,
pipe it into logs, commit it, add it to `.dev.vars`, or copy it into
docs/issues/test fixtures.

Use a long random value for `DJCONNECT_RELAY_SECRET`; never commit the value.
This is a bootstrap/operator secret only. Do not ship it in HACS or client
code. Public Home Assistant installations use per-install `djci_...` tokens
issued by `POST /v1/install/token`.

Generate `APNS_TOKEN_ENCRYPTION_KEY` as a base64-encoded 32-byte key and store
it only as a Cloudflare Worker secret:

```sh
openssl rand -base64 32
```

This key protects APNs device tokens stored in D1. Do not commit it, copy it
into GitHub Actions, or put it in `.dev.vars`/`.env`.

Automated equivalent:

```sh
DJCONNECT_RELAY_SECRET_VALUE='replace-with-long-random-secret' \
APNS_TOKEN_ENCRYPTION_KEY_VALUE="$(openssl rand -base64 32)" \
  scripts/provision_cloudflare.sh --execute --set-secrets \
  --apns-private-key-file /secure/path/to/key.p8
```

### 4. Apply Remote D1 Migration

Apply migrations remotely:

```sh
npx wrangler d1 migrations apply djconnect_api --remote
```

Automated equivalent:

```sh
scripts/provision_cloudflare.sh --execute --migrate
```

### 5. Deploy Worker

```sh
npm run deploy
```

Automated equivalent:

```sh
scripts/provision_cloudflare.sh --execute --deploy
```

### 6. Configure api.djconnect.dev

In Cloudflare, route the deployed Worker to:

```text
https://api.djconnect.dev
```

Then smoke test:

```sh
curl https://api.djconnect.dev/health
```

Expected response:

```json
{"ok":true,"service":"djconnect-api"}
```

Automated equivalent:

```sh
scripts/provision_cloudflare.sh --execute --custom-domain --smoke-test
```

The custom-domain step uses the Cloudflare API and requires a valid
`CLOUDFLARE_API_TOKEN` plus `CLOUDFLARE_ACCOUNT_ID`.

Non-secret APNs defaults are in `wrangler.jsonc`:

- `APNS_TEAM_ID=ZEML4LPXH4`
- `APNS_KEY_ID=929NDF6UYK`
- `APNS_TOPIC_IOS=dev.djconnect.ios`
- `APNS_TOPIC_MACOS=dev.djconnect.mac`
- `APNS_TOPIC_WATCHOS=dev.djconnect.watch`
- `APNS_ENVIRONMENT=sandbox`

Keep `APNS_ENVIRONMENT=sandbox` for development/TestFlight sandbox testing.
Switch to `production` only for production APNs release flows or use
environment-specific Wrangler configuration when added.

## Production Status

- `https://api.djconnect.dev/health` is live.
- Remote D1 migrations are applied.
- Cloudflare Worker secrets are configured for `APNS_PRIVATE_KEY`,
  `DJCONNECT_RELAY_SECRET` and `APNS_TOKEN_ENCRYPTION_KEY`.
- GitHub Actions CI/CD deploys `main` and smoke-tests `/health`.
- The latest release is `v1.0.2`.

## Development

```sh
npm install
npm test -- --run
npx tsc --noEmit
npm run dev
```

Deploy:

```sh
npm run deploy
```

The deployed production route is `https://api.djconnect.dev`; run the
`/health` smoke test above after deploys.

## CI/CD

GitHub Actions runs `Validate` on pull requests and pushes to `main`:

- `npm ci`
- `npx tsc --noEmit`
- `npx wrangler deploy --dry-run`
- `npm test -- --run`
- `npm run postman:test`
- public-repo secret pattern scan

Pushes to `main` also run the `Deploy` job:

- remote D1 migrations
- Worker deploy
- `https://api.djconnect.dev/health` smoke test
- `npm run postman:test`

Required GitHub Actions secret:

- `CLOUDFLARE_API_TOKEN`: Cloudflare API token with D1 migration, Workers
  deploy and Workers Routes edit permissions for the `djconnect_api` database,
  `djconnect-api` Worker and `djconnect.dev` zone.

Worker runtime secrets such as `APNS_PRIVATE_KEY`,
`DJCONNECT_RELAY_SECRET` and `APNS_TOKEN_ENCRYPTION_KEY` stay in Cloudflare
Worker secrets; do not copy them into GitHub Actions secrets unless a future
workflow explicitly needs them.

## Postman

The Postman collection lives at
`postman/djconnect-api.postman_collection.json`.

Run the privacy-safe contract smoke tests with:

```sh
npm run postman:test
```

The collection checks `/health` and unauthenticated negative cases for the
protected install/push endpoints. It intentionally uses only example values and
does not require or contain APNs tokens, install tokens, relay secrets, prompts,
assistant responses, Spotify tokens, Home Assistant tokens or chat history.

## Documentation

- `API_CONTRACT.md` documents endpoint payloads.
- `SECURITY.md` documents privacy, secret handling and responsible disclosure.
- `DEVELOPMENT_ENVIRONMENT.md` documents local setup and validation commands.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` document community contribution standards.
- `TECHNICAL_DESIGN_DECISIONS.md` records architecture and dependency decisions.
- `THIRD_PARTY_NOTICES.md` summarizes third-party APIs, tools and trademarks.
- `HANDOFF.md`, `TODO.md` and `ISSUES.md` track release state, next actions and known risks.
- `CHAT_BOOTSTRAP.md` gives fresh-chat context for AI-assisted maintenance.
- `scripts/provision_cloudflare.sh` automates Cloudflare secrets, migration,
  deploy, custom domain and smoke-test steps with dry-run-first safety.

## Release

Release hygiene follows the canonical cross-repo checklist in `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`. Use `CHANGELOG.md` as the GitHub Release body.

Use the cleanup helper during every release cycle. First inspect the dry-run:

```sh
./cleanup_old_releases.sh --keep 1
```

After the new GitHub Release is published and verified, delete old
releases/tags and old completed GitHub Actions workflow runs by default:

```sh
./cleanup_old_releases.sh --keep 1 --execute
```

Use `--keep-workflow-runs N` to keep more completed Actions runs, or
`--skip-workflow-runs` when preserving Actions history for an investigation.

## Notes

- `POST /v1/install/token` requires bootstrap auth with
  `DJCONNECT_RELAY_SECRET`.
- `POST /v1/push/register`, `/unregister`, `/event`, and
  `/v1/install/rotate` require a per-install token scoped to the request
  `ha_install_id`.
- APNs endpoint selection uses each registration's `apns_environment`.
- Invalid APNs tokens (`BadDeviceToken`, `Unregistered`, or HTTP 410) are marked disabled and invalid.
- Audit rows intentionally avoid prompts, responses, tokens, chat history, and secrets.
- New APNs registrations store device tokens encrypted at rest in D1 with
  `APNS_TOKEN_ENCRYPTION_KEY`. The legacy nullable `apns_token` column remains
  only as a migration fallback for old rows and should stay empty for new rows.

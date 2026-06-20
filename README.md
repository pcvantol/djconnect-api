# DJConnect API

Central Cloudflare Workers backend for DJConnect APNs push relay.

The Worker keeps the APNs `.p8` key server-side as a Cloudflare secret. Home Assistant and HACS integrations call this API with privacy-safe wake/sync events and never receive APNs provider credentials.

Current release: `1.0.1`.

## Cloudflare Setup

The D1 database already exists:

- `database_name`: `djconnect_api`
- `database_id`: `476a564f-08b2-4966-83b0-1221e2a4d063`
- binding: `DB`

Apply migrations locally:

```sh
npx wrangler d1 migrations apply djconnect_api --local
```

Apply migrations remotely:

```sh
npx wrangler d1 migrations apply djconnect_api --remote
```

Set required secrets:

```sh
npx wrangler secret put APNS_PRIVATE_KEY
npx wrangler secret put DJCONNECT_RELAY_SECRET
```

Do not print or commit the APNs private key. If setting from the local Apple key file, paste the contents into `wrangler secret put APNS_PRIVATE_KEY` when prompted.

Non-secret APNs defaults are in `wrangler.jsonc`:

- `APNS_TEAM_ID=ZEML4LPXH4`
- `APNS_KEY_ID=929NDF6UYK`
- `APNS_TOPIC_IOS=dev.djconnect.ios`
- `APNS_TOPIC_MACOS=dev.djconnect.mac`
- `APNS_TOPIC_WATCHOS=dev.djconnect.watch`
- `APNS_ENVIRONMENT=sandbox`

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

Route `api.djconnect.dev` to this Worker in Cloudflare after deploy.

## Documentation

- `API_CONTRACT.md` documents endpoint payloads.
- `SECURITY.md` documents privacy, secret handling and responsible disclosure.
- `DEVELOPMENT_ENVIRONMENT.md` documents local setup and validation commands.
- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` document community contribution standards.
- `TECHNICAL_DESIGN_DECISIONS.md` records architecture and dependency decisions.
- `THIRD_PARTY_NOTICES.md` summarizes third-party APIs, tools and trademarks.
- `HANDOFF.md`, `TODO.md` and `ISSUES.md` track release state, next actions and known risks.
- `CHAT_BOOTSTRAP.md` gives fresh-chat context for AI-assisted maintenance.

## Release

Release hygiene follows the canonical cross-repo checklist in `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`. Use `CHANGELOG.md` as the GitHub Release body.

Use the cleanup helper during every release cycle. First inspect the dry-run:

```sh
./cleanup_old_releases.sh --keep 1
```

After the new GitHub Release is published and verified, delete old releases/tags
by default:

```sh
./cleanup_old_releases.sh --keep 1 --execute
```

## Notes

- `POST /v1/push/register`, `/unregister`, and `/event` require relay auth.
- APNs endpoint selection uses each registration's `apns_environment`.
- Invalid APNs tokens (`BadDeviceToken`, `Unregistered`, or HTTP 410) are marked disabled and invalid.
- Audit rows intentionally avoid prompts, responses, tokens, chat history, and secrets.
- The `apns_token` column is plain storage for development relay support; replace it with encrypted-at-rest storage before production.

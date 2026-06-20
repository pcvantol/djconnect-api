# DJConnect API Development Environment

This document describes the local development setup for the DJConnect API
Cloudflare Worker.

## Repository

Work from the repository root:

```sh
cd /Users/pcvantol/Documents/GitHub/djconnect-api
```

The Worker source lives in:

```text
src/
```

D1 migrations live in:

```text
migrations/
```

## Required Tools

- Node.js compatible with the installed Wrangler/Vitest toolchain.
- npm.
- Wrangler through the project dependency (`npx wrangler ...`).
- GitHub CLI (`gh`) for release cleanup and GitHub Release operations.

Install dependencies with:

```sh
npm install
```

## Local Checks

Run these before release or non-trivial code changes:

```sh
npx wrangler types
npx tsc --noEmit
npm test
npx wrangler d1 migrations apply djconnect_api --local
git diff --check
```

The Worker test runner may need permission to write Wrangler logs under
`~/.wrangler` and start a local runtime listener.

## Local Development Server

Start the Worker locally:

```sh
npm run dev
```

The default local URL is usually:

```text
http://localhost:8787
```

Never put production secrets in `.dev.vars`, `.env` or test fixtures. Use only
example values locally.

## Cloudflare Configuration

The D1 binding is configured in `wrangler.jsonc`:

- binding: `DB`
- database name: `djconnect_api`
- migrations directory: `migrations`

Before remote operations, confirm the active Wrangler account or
`CLOUDFLARE_API_TOKEN` can edit Workers and D1 resources for the Cloudflare
account that owns database `476a564f-08b2-4966-83b0-1221e2a4d063`.

Previously observed blocked states:

- Remote D1 migration: Cloudflare error `7403`.
- Worker deploy: Wrangler/Cloudflare auth error `10000`.

Required secrets must be set through Cloudflare secrets/configuration:

```sh
npx wrangler secret put APNS_PRIVATE_KEY
npx wrangler secret put DJCONNECT_RELAY_SECRET
```

When setting `APNS_PRIVATE_KEY`, paste the full Apple `.p8` file contents into
the Wrangler prompt. Do not print the key or pipe it into shell history/logs.

Do not commit `.p8` files, `.dev.vars`, `.env`, API tokens or command output
that contains secrets.

After secrets, remote migration and deploy are configured, route the Worker to
`https://api.djconnect.dev` and smoke test:

```sh
curl https://api.djconnect.dev/health
```

## Migration Validation

Validate locally:

```sh
npx wrangler d1 migrations apply djconnect_api --local
```

Apply remotely only when Cloudflare account permissions are correct:

```sh
npx wrangler d1 migrations apply djconnect_api --remote
```

If Cloudflare returns account or token errors, document the skipped remote step
in `CHANGELOG.md` or `HANDOFF.md` and do not work around it by committing
credentials.

## Public Repository Secret Scan

Before every release, run:

```sh
rg -n "BEGIN PRIVATE KEY|AuthKey|DJCONNECT_RELAY_SECRET|APNS_PRIVATE_KEY|Bearer [A-Za-z0-9]|sk-|xox|ghp_|spotify_refresh|refresh_token|device_token" .
```

Allowed hits:

- Environment variable names.
- Placeholder documentation such as `Authorization: Bearer <DJCONNECT_RELAY_SECRET>`.
- Source code that parses PEM headers.
- Generated dependency comments or package integrity strings.
- Example test values.

Not allowed:

- Real APNs `.p8` content.
- Real relay secrets.
- Real APNs device tokens.
- Real Home Assistant, Spotify, GitHub or Cloudflare tokens.
- Production user, device or install identifiers.

## Development Hygiene

- Keep `README.md`, `API_CONTRACT.md`, `SECURITY.md`, `CHANGELOG.md`,
  `HANDOFF.md`, `TODO.md`, `ISSUES.md`, `TECHNICAL_DESIGN_DECISIONS.md`,
  `THIRD_PARTY_NOTICES.md`, `CHAT_BOOTSTRAP.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `AGENTS.md` and this file current when workflow,
  public contracts or security assumptions change.
- Keep cross-repo sync prompts and product roadmap only in
  `/Users/pcvantol/Documents/GitHub/djconnect`.
- Do not include secrets, private data or proprietary third-party material in
  prompts, agent logs, screenshots, issues or test fixtures.
- Release cleanup is part of the normal release cycle: run
  `./cleanup_old_releases.sh --keep 1` as a dry-run first, then
  `./cleanup_old_releases.sh --keep 1 --execute` after the new GitHub Release
  is published and verified.

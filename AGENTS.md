# Cloudflare Workers

## DJConnect Platform Bootstrap

For a clean Codex/AI-agent session, first follow the canonical platform bootstrap:

`pcvantol/djconnect/BOOTSTRAP_CODEX_SESSION.md`

Then continue with the repository-specific instructions in this file.

This repository extends the DJConnect Platform Foundation. It does not redefine it.

This must be additive only. Existing repo-specific AGENTS guidance remains authoritative for implementation details.


This repository follows the canonical DJConnect design foundation in `pcvantol/djconnect`.

Before product, protocol, trust, privacy, release or CI changes, consult the canonical foundation docs in the HA integration repo:

- `DJCONNECT_CONSTITUTION.md`
- `PRODUCT_VISION.md`
- `DESIGN_PRINCIPLES.md`
- `ARCHITECTURE_PRINCIPLES.md`
- `DOMAIN_MODEL.md`
- `CLIENT_CAPABILITY_MATRIX.md`
- `PRODUCT_LANGUAGE.md`
- `PLATFORM_GOVERNANCE.md`
- `PLATFORM_QUALITY_STANDARD.md`
- `SYNC_PROMPTS.md`
- `PRODUCT_ROADMAP.md`

Repo-local Cloudflare/API/security rules below remain authoritative for API-specific work.

STOP. Your knowledge of Cloudflare Workers APIs and limits may be outdated. Always retrieve current documentation before any Workers, KV, R2, D1, Durable Objects, Queues, Vectorize, AI, or Agents SDK task.

This repository is public/open-source safe by default. Never commit APNs `.p8`
private keys, `DJCONNECT_RELAY_SECRET`, `DJCONNECT_PAIRING_ISSUER_SECRET`,
real APNs device tokens, Home Assistant tokens, Spotify tokens, Cloudflare API
tokens, production user/install/device IDs, raw prompts, raw assistant
responses, full chat history or logs containing request bodies.

Use only example fixture values such as `example-ha-install`,
`example-user-hash`, `example-apns-token` and `dev.djconnect.ios`.

Cross-repo source of truth:

- `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/PRODUCT_ROADMAP.md`

Do not copy cross-repo prompt or roadmap files into this repository.

## Docs

- https://developers.cloudflare.com/workers/
- MCP: `https://docs.mcp.cloudflare.com/mcp`

For all limits and quotas, retrieve from the product's `/platform/limits/` page. eg. `/workers/platform/limits`

## Commands

| Command | Purpose |
|---------|---------|
| `npx wrangler dev` | Local development |
| `npx wrangler deploy` | Deploy to Cloudflare |
| `npx wrangler types` | Generate TypeScript types |
| `npx tsc --noEmit` | Type check |
| `npm test` | Run Worker tests |
| `npx wrangler d1 migrations apply djconnect_api --local` | Validate D1 migrations locally |
| `./cleanup_old_releases.sh --keep 1` | Dry-run release/tag cleanup |
| `./cleanup_old_releases.sh --keep 1 --execute` | Delete old releases/tags after a verified release |

Run `wrangler types` after changing bindings in wrangler.jsonc.

Before release, also run:

```sh
git diff --check
rg -n "BEGIN PRIVATE KEY|AuthKey|DJCONNECT_RELAY_SECRET|DJCONNECT_PAIRING_ISSUER_SECRET|APNS_PRIVATE_KEY|Bearer [A-Za-z0-9]|sk-|xox|ghp_|spotify_refresh|refresh_token|device_token" .
```

Hits for env-var names/placeholders/source parsing/generated comments are ok.
Real secret values are not.

Also review translations in all five supported languages before every release:
`en`, `nl`, `de`, `fr` and `es`.

## Node.js Compatibility

https://developers.cloudflare.com/workers/runtime-apis/nodejs/

## Errors

- **Error 1102** (CPU/Memory exceeded): Retrieve limits from `/workers/platform/limits/`
- **All errors**: https://developers.cloudflare.com/workers/observability/errors/

## Product Docs

Retrieve API references and limits from:
`/kv/` · `/r2/` · `/d1/` · `/durable-objects/` · `/queues/` · `/vectorize/` · `/workers-ai/` · `/agents/`

## Best Practices (conditional)

If the application uses Durable Objects or Workflows, refer to the relevant best practices:

- Durable Objects: https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- Workflows: https://developers.cloudflare.com/workflows/build/rules-of-workflows/

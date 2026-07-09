# DJConnect Agent Guidance

This repository follows the DJConnect design foundation maintained in `pcvantol/djconnect`.

Before changing product behavior, architecture, public contracts, release behavior, security/privacy behavior, or cross-repo protocol, read the source-of-truth documents in the Home Assistant integration repo:

1. `DJCONNECT_CONSTITUTION.md`
2. `PRODUCT_VISION.md`
3. `DESIGN_PRINCIPLES.md`
4. `ARCHITECTURE_PRINCIPLES.md`
5. `CI_CD_RELEASE_GOVERNANCE.md`
6. `PRODUCT_ROADMAP.md`
7. `INNOVATION_LAB.md`
8. `SYNC_PROMPTS.md`

The Constitution wins when prompts or issues conflict.

## Repository role

`pcvantol/djconnect-api` is the central API / trust boundary. It currently supports APNs relay and device/install trust responsibilities and can later become the entitlement and optional cloud boundary.

It should not become the primary local intelligence source and should not duplicate Home Assistant integration business logic unless an explicit architecture decision says otherwise.

## Cloudflare Workers

STOP. Your knowledge of Cloudflare Workers APIs and limits may be outdated. Always retrieve current documentation before any Workers, KV, R2, D1, Durable Objects, Queues, Vectorize, AI, or Agents SDK task.

This repository is public/open-source safe by default. Never commit APNs `.p8` private keys, `DJCONNECT_RELAY_SECRET`, `DJCONNECT_PAIRING_ISSUER_SECRET`, real APNs device tokens, Home Assistant tokens, Spotify tokens, Cloudflare API tokens, production user/install/device IDs, raw prompts, raw assistant responses, full chat history or logs containing request bodies.

Use only example fixture values such as `example-ha-install`, `example-user-hash`, `example-apns-token` and `dev.djconnect.ios`.

Cross-repo source of truth:

- `pcvantol/djconnect/DJCONNECT_CONSTITUTION.md`
- `pcvantol/djconnect/PRODUCT_VISION.md`
- `pcvantol/djconnect/DESIGN_PRINCIPLES.md`
- `pcvantol/djconnect/ARCHITECTURE_PRINCIPLES.md`
- `pcvantol/djconnect/CI_CD_RELEASE_GOVERNANCE.md`
- `pcvantol/djconnect/SYNC_PROMPTS.md`
- `pcvantol/djconnect/API_CONTRACT.md`
- `pcvantol/djconnect/PRODUCT_ROADMAP.md`

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

Hits for env-var names/placeholders/source parsing/generated comments are ok. Real secret values are not.

Also review translations in all five supported languages before every release: `en`, `nl`, `de`, `fr` and `es`.

## Node.js Compatibility

https://developers.cloudflare.com/workers/runtime-apis/nodejs/

## Errors

- **Error 1102** (CPU/Memory exceeded): Retrieve limits from `/workers/platform/limits/`
- **All errors**: https://developers.cloudflare.com/workers/observability/errors/

## Product Docs

Retrieve API references and limits from: `/kv/` · `/r2/` · `/d1/` · `/durable-objects/` · `/queues/` · `/vectorize/` · `/workers-ai/` · `/agents/`

## Best Practices (conditional)

If the application uses Durable Objects or Workflows, refer to the relevant best practices:

- Durable Objects: https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- Workflows: https://developers.cloudflare.com/workflows/build/rules-of-workflows/

# DJConnect API Agent Instructions

This repository follows the canonical DJConnect design foundation in `pcvantol/djconnect`.

Read first:

1. `pcvantol/djconnect/DJCONNECT_CONSTITUTION.md`
2. `pcvantol/djconnect/PRODUCT_VISION.md`
3. `pcvantol/djconnect/DESIGN_PRINCIPLES.md`
4. `pcvantol/djconnect/ARCHITECTURE_PRINCIPLES.md`
5. `pcvantol/djconnect/SYNC_PROMPTS.md`

## Role

This repo owns the central API boundary: APNs relay, install/device trust, privacy-safe wake events and future entitlement/profile-cloud surfaces.

The API is not the primary local intelligence source. It extends the local-first DJConnect platform.

## Foundation rules

- Preserve the Profile-first model for future Personal/Cloud features.
- Do not make local Home Assistant functionality depend on cloud-only APIs.
- Store and expose the minimum personal data needed for relay/trust/entitlement purposes.
- APNs secrets, relay secrets, tokens and production identifiers must never appear in source, logs or release artifacts.
- Future cloud capabilities must enhance Community, not replace it.

## Cloudflare Workers

STOP. Your knowledge of Cloudflare Workers APIs and limits may be outdated. Always retrieve current documentation before any Workers, KV, R2, D1, Durable Objects, Queues, Vectorize, AI, or Agents SDK task.

This repository is public/open-source safe by default. Never commit APNs `.p8` private keys, `DJCONNECT_RELAY_SECRET`, `DJCONNECT_PAIRING_ISSUER_SECRET`, real APNs device tokens, Home Assistant tokens, Spotify tokens, Cloudflare API tokens, production user/install/device IDs, raw prompts, raw assistant responses, full chat history or logs containing request bodies.

Use only example fixture values such as `example-ha-install`, `example-user-hash`, `example-apns-token` and `dev.djconnect.ios`.

## Commands

| Command | Purpose |
|---------|---------|
| `npx wrangler dev` | Local development |
| `npx wrangler deploy` | Deploy to Cloudflare |
| `npx wrangler types` | Generate TypeScript types |
| `npx tsc --noEmit` | Type check |
| `npm test` | Run Worker tests |
| `npx wrangler d1 migrations apply djconnect_api --local` | Validate D1 migrations locally |

Run `wrangler types` after changing bindings in `wrangler.jsonc`.

Before release, also run:

```sh
git diff --check
rg -n "BEGIN PRIVATE KEY|AuthKey|DJCONNECT_RELAY_SECRET|DJCONNECT_PAIRING_ISSUER_SECRET|APNS_PRIVATE_KEY|Bearer [A-Za-z0-9]|sk-|xox|ghp_|spotify_refresh|refresh_token|device_token" .
```

Hits for env-var names/placeholders/source parsing/generated comments are ok. Real secret values are not.

Also review translations in all supported languages before every release.

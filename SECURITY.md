# Security and Privacy

## Secrets

Never commit or return:

- APNs `.p8` private key
- Home Assistant tokens
- Spotify tokens
- Cloudflare API tokens
- Relay shared secret

Store production secrets with `wrangler secret put`.

Secrets and production configuration must be set only through Cloudflare secrets/configuration. Do not place secrets in source files, tests, docs, fixtures, `.dev.vars`, `.env`, or migration files.

## Relay Auth

All `/v1/push/*` calls require relay auth. The initial implementation supports a shared bearer secret and HMAC signatures. Per-install tokens can be added later without changing the APNs trust boundary.

## Data Minimization

This API stores only push routing metadata and minimal audit rows. It must not store:

- raw user prompts
- raw assistant responses
- full chat history
- memory
- Home Assistant API tokens
- Spotify tokens
- APNs provider key material

Apple push payloads are generic wake/sync signals. Clients fetch current data from their own Home Assistant instance after opening.

## Logging

Logs must only contain token hashes or redacted token snippets. Do not log request bodies for `/v1/push/register` or `/v1/push/event`.

## Token Handling

APNs tokens are hashed for lookup/audit. The current schema includes `apns_token` in plain form so development can relay pushes immediately; before production, replace this with encryption at rest or another protected token storage strategy.

## Responsible Disclosure

Please report security issues privately to the DJConnect maintainers instead of opening a public issue with exploit details, secrets, tokens, or user data. Include enough information to reproduce the issue without sharing production credentials.

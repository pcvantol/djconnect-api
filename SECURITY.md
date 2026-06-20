# Security and Privacy

## Secrets

Never commit or return:

- APNs `.p8` private key
- Home Assistant tokens
- Spotify tokens
- Cloudflare API tokens
- Relay shared secret

Store production secrets with `wrangler secret put`.

The repository also provides `scripts/provision_cloudflare.sh` for automated
setup. It is dry-run by default, refuses shell tracing and does not echo secret
values. Provide APNs key material through `--apns-private-key-file` and the
relay secret through an environment variable such as
`DJCONNECT_RELAY_SECRET_VALUE`; never pass secret values directly in shell
arguments.

Secrets and production configuration must be set only through Cloudflare secrets/configuration. Do not place secrets in source files, tests, docs, fixtures, `.dev.vars`, `.env`, or migration files.

Required Cloudflare secrets:

- `APNS_PRIVATE_KEY`: full Apple `.p8` private key content. Paste it into
  `npx wrangler secret put APNS_PRIVATE_KEY` when prompted. Never print, log,
  commit or paste the key into issues.
- `DJCONNECT_RELAY_SECRET`: long random relay shared secret for authenticated
  HA -> API calls. Never commit the value.

The APNs public metadata is allowed in source/config:

- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- APNs topics for iOS, macOS and watchOS
- `APNS_ENVIRONMENT`

Cloudflare API tokens are operator credentials. Do not commit them, put them in
docs, or include them in command output shared publicly.

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

This is the main blocker before production APNs traffic. Do not treat the
current `apns_token` column as production-hardened storage.

## Responsible Disclosure

Please report security issues privately to the DJConnect maintainers instead of opening a public issue with exploit details, secrets, tokens, or user data. Include enough information to reproduce the issue without sharing production credentials.

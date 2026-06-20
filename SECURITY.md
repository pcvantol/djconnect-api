# Security and Privacy

## Secrets

Never commit or return:

- APNs `.p8` private key
- Home Assistant tokens
- Spotify tokens
- Cloudflare API tokens
- Relay/bootstrap shared secret
- Per-install DJConnect relay tokens

Store production secrets with `wrangler secret put`.

The repository also provides `scripts/provision_cloudflare.sh` for automated
setup. It is dry-run by default, supports explicit `--dry-run`, refuses shell
tracing and does not echo secret values. Provide APNs key material through
`--apns-private-key-file` and the relay secret through an environment variable such as
`DJCONNECT_RELAY_SECRET_VALUE`. Provide the APNs token encryption key through
an environment variable such as `APNS_TOKEN_ENCRYPTION_KEY_VALUE`; never pass
secret values directly in shell arguments.

In execute mode, the script requires and verifies `CLOUDFLARE_API_TOKEN` before
running Cloudflare-changing actions. A valid token alone is not enough for every
operation; it must also have account permissions for Workers, D1 and custom
domain management.

Secrets and production configuration must be set only through Cloudflare secrets/configuration. Do not place secrets in source files, tests, docs, fixtures, `.dev.vars`, `.env`, or migration files.

Required Cloudflare secrets:

- `APNS_PRIVATE_KEY`: full Apple `.p8` private key content. Paste it into
  `npx wrangler secret put APNS_PRIVATE_KEY` when prompted. Never print, log,
  commit or paste the key into issues.
- `DJCONNECT_RELAY_SECRET`: long random relay shared secret for authenticated
  trusted bootstrap/operator calls that issue per-install tokens. Never commit
  the value. Do not ship it in HACS or client code.
- `APNS_TOKEN_ENCRYPTION_KEY`: base64-encoded 32-byte key used to encrypt APNs
  device tokens before D1 storage. Generate with `openssl rand -base64 32`.
  Never commit, print, log, or copy it into GitHub Actions.

The APNs public metadata is allowed in source/config:

- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- APNs topics for iOS, macOS and watchOS
- `APNS_ENVIRONMENT`

Cloudflare API tokens are operator credentials. Do not commit them, put them in
docs, or include them in command output shared publicly.

## Relay Auth

Public HACS integrations must not contain a global DJConnect secret.

The production auth model is:

- `DJCONNECT_RELAY_SECRET` stays server/operator-side and is used only for
  trusted bootstrap calls such as `POST /v1/install/token`.
- Each Home Assistant installation receives its own `djci_...` install token.
- `/v1/push/register`, `/v1/push/unregister`, `/v1/push/event` and
  `/v1/install/rotate` require the per-install token for the exact
  `ha_install_id` in the request body.
- Install tokens are stored in D1 only as SHA-256 hashes. The raw token is
  returned once and must be stored in Home Assistant config entry storage.
- Rotate or disable a compromised install token without affecting other
  installations.

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

APNs tokens are hashed for lookup/audit and encrypted before D1 storage with
AES-GCM using `APNS_TOKEN_ENCRYPTION_KEY`. New registrations write encrypted
token material to `apns_token_ciphertext`, `apns_token_nonce` and
`apns_token_key_version`; the raw nullable `apns_token` column is retained only
as a legacy migration fallback for older rows.

Rotate the encryption key only with a deliberate re-encryption/backfill plan.
Do not log decrypted APNs tokens; use hashes or redacted snippets only.

## Responsible Disclosure

Please report security issues privately to the DJConnect maintainers instead of opening a public issue with exploit details, secrets, tokens, or user data. Include enough information to reproduce the issue without sharing production credentials.

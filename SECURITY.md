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
- `DJCONNECT_PAIRING_ISSUER_SECRET`: separate long random shared secret for the
  trusted Apple pairing issuer flow. Never commit the value. Do not ship it in
  HACS or client code.
- `APNS_TOKEN_ENCRYPTION_KEY`: base64-encoded 32-byte key used to encrypt APNs
  device tokens before D1 storage. Generate with `openssl rand -base64 32`.
  Never commit, print, log, or copy it into GitHub Actions.
- `DJCONNECT_SMOKE_TEST_MODE`: optional Worker secret. Set to `enabled` only to
  allow CI to run the staging-safe E2E path with `example-...` APNs tokens
  without contacting APNs. The Worker still uses real APNs for all non-example
  tokens.

The APNs public metadata is allowed in source/config:

- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- APNs topics for iOS, macOS and watchOS
- `APNS_ENVIRONMENT`

Cloudflare API tokens are operator credentials. Do not commit them, put them in
docs, or include them in command output shared publicly.

GitHub Actions may contain `DJCONNECT_RELAY_SECRET` only for the staging-safe
E2E smoke test. Do not expose it to pull requests from untrusted forks, logs, or
non-CI tooling.

## Relay Auth

Public HACS integrations must not contain a global DJConnect secret.

The production auth model is:

- `DJCONNECT_RELAY_SECRET` stays server/operator-side and is used only for
  trusted admin/pairing calls such as `POST /v1/install/bootstrap-proof`.
- `DJCONNECT_PAIRING_ISSUER_SECRET` stays in the trusted pairing issuer
  environment and is used only for `POST /v1/pairing/bootstrap-proof`.
- Each Home Assistant installation receives its own `djci_...` install token.
  The HACS integration provisions this automatically during setup; users do not
  normally paste tokens manually. `POST /v1/install/token` requires a
  short-lived one-time `djcboot_...` proof and does not accept
  `DJCONNECT_RELAY_SECRET` as a fallback.
- Bootstrap proofs are stored hashed, bound to `ha_install_id`, `client_type`
  and `device_id`, expire quickly and are marked used after successful token
  issuance. They are only for Apple push clients (`ios`, `macos`, `watchos`);
  ESP32, Raspberry Pi, Windows and Assist-agent-only entries do not use APNs
  push and must not request central API bootstrap proofs.
- Bootstrap proof consumption is D1 rate-limited by hashed IP, install ID and
  device ID keys. Rate-limit rows must not store raw proofs or tokens.
- `/v1/push/register`, `/v1/push/unregister`, `/v1/push/event` and
  `/v1/install/rotate` require the per-install token for the exact
  `ha_install_id` in the request body.
- Install tokens are stored in D1 only as SHA-256 hashes. The raw token is
  returned once and is stored by the integration in Home Assistant config entry
  options.
- Rotate tokens with `/v1/install/rotate` using the current per-install token,
  or disable a compromised token with the operator-only
  `/v1/operator/install-token/revoke` endpoint. Revoke requests use
  `ha_install_id` plus token ID, never raw `djci_...` token material, and do
  not issue a replacement token.
- Admin endpoints such as `GET /v1/admin/registrations` require the
  bootstrap/operator secret and explicitly reject per-install `djci_...` tokens.

Support/options UI may expose API URL/token inspection, replacement or
rotation controls, but those are operator support paths. They are not the
standard user onboarding path and must not reveal global secrets.

## Data Minimization

This API stores only push routing metadata and minimal audit rows. It must not store:

- raw user prompts
- raw assistant responses
- full chat history
- memory
- Home Assistant API tokens
- Spotify tokens
- APNs provider key material

Apple push payloads are generic wake/sync signals. Send APNs only for
`ask_dj_response` and `ask_dj_confirm`; do not push playback, track, queue,
volume, mood, idle, status, polling or Spotify progress updates. Clients fetch
current data from their own Home Assistant instance after opening.

## Admin Data Exposure

Admin views must be privacy-safe summaries. `GET /v1/admin/registrations`
returns only operational metadata needed by the DJConnect admin website:
registration ID, hashed install/device identifiers, Home Assistant user hash,
client type, APNs environment, APNs topic, app metadata, locale, categories,
disabled/invalid flags and timestamps.

Admin responses must never include raw APNs tokens, APNs token ciphertext,
nonces, encryption key versions, provider keys, relay secrets, Home Assistant
tokens, Spotify tokens, raw prompts, assistant responses or chat history. The
admin website must read through the admin API and must not query D1 directly.

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
The operator procedure lives in `OPERATOR_RUNBOOK.md`.

## Responsible Disclosure

Please report security issues privately to the DJConnect maintainers instead of opening a public issue with exploit details, secrets, tokens, or user data. Include enough information to reproduce the issue without sharing production credentials.

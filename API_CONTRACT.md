# API Contract

Base URL: `https://api.djconnect.dev`

Postman collection:
`postman/djconnect-api.postman_collection.json`

The collection is intentionally privacy-safe: it tests `/health` and
unauthenticated negative cases only, using example values and no secrets.

Production auth uses per-install tokens. HACS integrations provision and store
their own per-install `djci_...` token automatically; they must never embed a
global DJConnect secret.

Bootstrap/operator auth is only for trusted admin/pairing flows that issue
short-lived bootstrap proofs:

```http
Authorization: Bearer <DJCONNECT_RELAY_SECRET>
```

HMAC auth is also supported with:

- `x-djconnect-timestamp`: Unix seconds
- `x-djconnect-signature`: `sha256=<hex_hmac_sha256(timestamp + "." + raw_body)>`

Push/register/event auth uses a per-install token:

```http
Authorization: Bearer <djci_install_token>
```

## GET /health

Public liveness check.

Response:

```json
{ "ok": true, "service": "djconnect-api" }
```

## POST /v1/install/bootstrap-proof

Issues a short-lived, one-time bootstrap proof for an existing
pairing/provisioning context. This is an operator/admin pairing endpoint and is
not called by public HACS code with a bundled global secret.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "integration": "djconnect_hacs",
  "integration_version": "3.1.0",
  "client_type": "ios",
  "device_id": "example-device",
  "pairing_session_id": "example-pairing-session",
  "ttl_seconds": 600
}
```

Response:

```json
{
  "ok": true,
  "id": "bootstrap-proof-id",
  "bootstrap_proof": "djcboot_example-bootstrap-proof-returned-once",
  "proof_hash": "sha256-hex",
  "expires_at": "2026-06-20T12:00:00.000Z"
}
```

The API stores only the proof hash. The raw proof is returned once, must not be
logged, and expires after a short TTL. Proofs are bound to `ha_install_id`,
`client_type` and `device_id`.

## POST /v1/install/token

Issues a per-install token. This endpoint is proof-only: it does not accept
`DJCONNECT_RELAY_SECRET`/operator auth as a fallback. Public HACS code must
never contain a bundled global secret.

The Home Assistant integration's normal user flow is automatic provisioning:
it creates/persists `ha_install_id`, obtains a per-install token during setup,
stores it in Home Assistant config entry options and uses that token for
central API calls. Manual API URL/token controls are support/override tools,
not a required onboarding step.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "ha_user_hash": "example-user-hash",
  "label": "example-ha",
  "integration": "djconnect_hacs",
  "integration_version": "3.1.0",
  "client_type": "ios",
  "device_id": "example-device",
  "bootstrap_proof": "djcboot_example-bootstrap-proof-returned-once"
}
```

Response:

```json
{
  "ok": true,
  "success": true,
  "id": "install-token-id",
  "token": "djci_example-install-token-returned-once",
  "install_token": "djci_example-install-token-returned-once",
  "token_hash": "sha256-hex",
  "expires_at": null
}
```

Store the returned token in Home Assistant config entry storage. The raw token
is returned once and is stored by the API only as a SHA-256 hash.

Failure codes:

- `invalid_bootstrap_proof`
- `bootstrap_proof_expired`
- `bootstrap_proof_used`
- `install_id_mismatch`
- `bootstrap_rate_limited`

## POST /v1/install/rotate

Rotates the token for one Home Assistant installation. Requires the current
per-install token for the same `ha_install_id`.

Request:

```json
{
  "ha_install_id": "example-ha-install"
}
```

Response:

```json
{
  "ok": true,
  "id": "new-install-token-id",
  "token": "djci_new-example-install-token-returned-once",
  "token_hash": "sha256-hex"
}
```

## POST /v1/push/register

Registers or updates one Apple client device.

Requires the per-install token for the same `ha_install_id`.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "ha_user_hash": "example-user-hash",
  "device_id": "example-device",
  "client_type": "ios",
  "apns_token": "example-apns-token",
  "apns_environment": "sandbox",
  "app_bundle_id": "dev.djconnect.ios",
  "app_version": "1.0.0",
  "locale": "nl-NL",
  "categories": ["ask_dj"]
}
```

Response:

```json
{
  "ok": true,
  "id": "registration-id",
  "apns_token_hash": "sha256-hex"
}
```

Storage note: the API hashes APNs tokens for lookup/audit and encrypts token
material before D1 storage. Raw APNs tokens must not be logged or stored in
docs, fixtures or client-visible audit data.

## POST /v1/push/unregister

Disables a registration.

Requires the per-install token for the same `ha_install_id`.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "device_id": "example-device",
  "client_type": "ios",
  "apns_token": "example-apns-token"
}
```

Response:

```json
{ "ok": true, "disabled": 1 }
```

## POST /v1/push/event

Relays a generic push notification to active registrations for a Home Assistant install.

Requires the per-install token for the same `ha_install_id`.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "ha_user_hash": "example-user-hash",
  "event_type": "ask_dj_response",
  "history_revision": "42",
  "client_message_id": "example-client-message",
  "open_target": "history",
  "client_types": ["ios", "watchos"]
}
```

Allowed `event_type` values:

- `ask_dj_response`: sends "Ask DJ heeft geantwoord."
- `ask_dj_confirm`: sends "Ask DJ wacht op je keuze."
- `playback_change`: sends a generic DJConnect update

Response:

```json
{
  "ok": true,
  "matched": 2,
  "delivered": 2,
  "failed": 0
}
```

The event body must not include raw prompts, raw assistant responses, Spotify tokens, HA tokens, or chat history.

Clients should open and sync directly with their own Home Assistant instance, especially `/api/djconnect/ask_dj/history`.

## GET /v1/admin/registrations

Returns a privacy-safe operator overview of registered Apple client devices for
the DJConnect admin website.

Requires bootstrap/operator auth using `DJCONNECT_RELAY_SECRET` through bearer
auth or HMAC signature. Per-install `djci_...` tokens are rejected and must not
be used by admin tooling.

Query parameters:

- `limit`: page size from 1 to 100. Default: 50.
- `offset`: zero-based row offset. Default: 0.
- `cursor`: alias for `offset`.
- `client_type`: optional `ios`, `macos` or `watchos`.
- `apns_environment`: optional `sandbox` or `production`.
- `disabled`: optional `true`, `false`, `1` or `0`.
- `invalid`: optional `true`, `false`, `1` or `0`.
- `ha_install_id`: optional exact install filter. The raw value is accepted
  only as an operator filter and is not returned.

Example:

```http
GET /v1/admin/registrations?client_type=ios&disabled=false&limit=25
Authorization: Bearer <DJCONNECT_RELAY_SECRET>
```

Response:

```json
{
  "ok": true,
  "registrations": [
    {
      "id": "registration-id",
      "ha_install_id_hash": "0123456789abcdef",
      "ha_user_hash": "example-user-hash",
      "device_id_hash": "abcdef0123456789",
      "client_type": "ios",
      "apns_environment": "sandbox",
      "topic": "dev.djconnect.ios",
      "app_bundle_id": "dev.djconnect.ios",
      "app_version": "1.0.0",
      "locale": "nl-NL",
      "categories": ["ask_dj"],
      "disabled": false,
      "invalid": false,
      "created_at": "2026-06-20 12:00:00",
      "updated_at": "2026-06-20 12:10:00",
      "last_success_at": "2026-06-20 12:10:00",
      "last_error_code": null,
      "apns_token_hash_prefix": "0123456789ab"
    }
  ],
  "next_offset": null
}
```

The response never includes raw APNs tokens, APNs token ciphertext, nonces,
encryption key versions, relay secrets, Home Assistant tokens, Spotify tokens,
prompts, responses or chat history. Install and device identifiers are returned
only as stable SHA-256 prefixes.

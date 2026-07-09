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

## Error Responses

Error responses keep the language-neutral `error` code stable for clients. If a
client sends `Accept-Language` or a `lang` query parameter, the response may also
include a localized `message` in one of the supported languages: `en`, `nl`,
`de`, `fr` or `es`. `Accept-Language` quality values are honored across
supported languages. Unsupported locales fall back to the best supported
language in the header, or English when none is present.

Example:

```json
{
  "error": "missing_bootstrap_proof",
  "message": "The bootstrap proof is required."
}
```

Clients must make decisions from `error`, not from localized message text.

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
`client_type` and `device_id`. Proofs are only issued for Apple push clients:
`ios`, `macos` and `watchos`. ESP32, Raspberry Pi, Windows and
Assist-agent-only entries do not use APNs push and must not request central API
bootstrap proofs.

## POST /v1/pairing/bootstrap-proof

Issues a short-lived, one-time bootstrap proof for the Apple client pairing
issuer flow. This endpoint is client-safe: Apple clients do not include
`DJCONNECT_PAIRING_ISSUER_SECRET`, `DJCONNECT_RELAY_SECRET`, APNs provider keys
or backend tokens. The API validates known DJConnect Apple app metadata and
returns privacy-safe errors when a proof is unavailable.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "integration": "djconnect_hacs",
  "integration_version": "3.2.37",
  "client_type": "macos",
  "device_id": "djconnect-macos-XXXXXXXXXXXX",
  "pairing_session_id": "example-pairing-session",
  "app_bundle_id": "dev.djconnect.mac",
  "push_environment": "production"
}
```

Response:

```json
{
  "ok": true,
  "success": true,
  "bootstrap_proof": "djcboot_example-bootstrap-proof-returned-once",
  "expires_at": "2026-07-08T12:10:00.000Z"
}
```

The API stores only the proof hash and binds the proof to `ha_install_id`,
`client_type`, `device_id` and `pairing_session_id`. The request must use a
known app bundle ID, a matching Apple client type, a non-empty
`pairing_session_id`, `sandbox` or `production` push environment, and a stable
DJConnect Apple device ID.

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
The proof format is `djcboot_...`; validity is checked against D1 by proof
hash, `ha_install_id`, `client_type`, `device_id`, expiry and one-time
consumption. The proof must have been issued and registered by the central API;
a locally generated HA or Apple client proof is rejected as
`invalid_bootstrap_proof`. `app_bundle_id`, `push_environment` and APNs
token/provider key material are not required for install-token minting.

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

## POST /v1/operator/install-token/revoke

Disables one compromised per-install token without issuing a replacement.
This endpoint is for the DJConnect operator/admin website.

Requires bootstrap/operator auth using `DJCONNECT_RELAY_SECRET` through bearer
auth or HMAC signature. Per-install `djci_...` tokens are rejected and must not
be used by admin tooling.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "token_id": "install-token-id",
  "reason": "operator-disabled-compromised-install"
}
```

Response:

```json
{
  "ok": true,
  "revoked": 1
}
```

`revoked` is `1` when an active token was disabled and `0` when no active token
matched that `ha_install_id`/`token_id` pair. The API stores `revoked_at` and
an optional short `revoke_reason`; do not put raw tokens, user data, prompts or
secrets in `reason`.

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
  "announcement": {
    "delivery": "both",
    "audio_available": true,
    "speaker_delivery": "attempted"
  },
  "client_types": ["ios", "watchos"]
}
```

Allowed `event_type` values:

- `ask_dj_response`: sends a concise localized "Ask DJ has replied" alert.
- `ask_dj_confirm`: sends a concise localized "Ask DJ is waiting" alert.

Push policy is strict: central APNs events are only for Ask DJ replies after an
explicit user Ask DJ request and Ask DJ confirmations waiting for a user choice.
Do not send APNs for track, playback, queue, volume, mood, idle suggestion,
ambient/system, status, polling or Spotify progress updates.

APNs alert text is selected from the registered client `locale` when available.
Supported languages are `en`, `nl`, `de`, `fr` and `es`; unsupported locales
fall back to English. APNs payload keys, event values and `open_target` values
are protocol fields and are never localized.

`ask_dj_response` may include an optional privacy-safe `announcement` hint.
Only these compact metadata fields are accepted and forwarded to APNs:

- `delivery`: `client_device`, `both`, `ha_speaker` or `text_only`.
- `audio_available`: boolean.
- `speaker_delivery`: `attempted` or `none`.

Invalid announcement enum values and any other announcement keys are stripped.
Forbidden fields such as `audio_url`, `text`, `dj_text`, `message`, `prompt`,
`history`, `memory`, `raw_audio`, token/secret/authorization values and nested
target/entity metadata are never stored, logged, returned or included in APNs
payloads. APNs remains a wake/sync/attention signal only: it must not carry TTS
audio, temporary audio URLs, full DJ text, prompts, Ask DJ history or Music DNA.
Clients must sync the canonical Ask DJ response over HTTP, websocket or history
after receiving push before deciding any local announcement autoplay behavior.

Response:

```json
{
  "ok": true,
  "matched": 2,
  "delivered": 2,
  "failed": 0
}
```

The event body must not include raw prompts, raw assistant responses, Spotify
tokens, HA tokens, chat history, TTS audio or temporary audio URLs.

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

## GET /v1/admin/diagnostics

Returns a privacy-safe production diagnostics summary for the DJConnect admin
website and operator investigations.

Requires bootstrap/operator auth using `DJCONNECT_RELAY_SECRET` through bearer
auth or HMAC signature. Per-install `djci_...` tokens are rejected and must not
be used by admin tooling.

Query parameters:

- `since_hours`: optional diagnostics window from 1 to 720 hours. Default: 24.

Example:

```http
GET /v1/admin/diagnostics?since_hours=24
Authorization: Bearer <DJCONNECT_RELAY_SECRET>
```

Response:

```json
{
  "ok": true,
  "generated_at": "2026-07-04T06:00:00.000Z",
  "window_hours": 24,
  "registrations": {
    "total": 3,
    "active": 2,
    "disabled": 1,
    "invalid": 1,
    "by_client": [
      {
        "client_type": "ios",
        "apns_environment": "sandbox",
        "disabled": false,
        "invalid": false,
        "count": 2
      }
    ]
  },
  "registration_errors": [
    {
      "code": "BadDeviceToken",
      "count": 1
    }
  ],
  "relay": {
    "events": 4,
    "targeted": 5,
    "delivered": 4,
    "failed": 1,
    "by_event": [
      {
        "event_type": "ask_dj_response",
        "client_type": null,
        "events": 4,
        "targeted": 5,
        "delivered": 4,
        "failed": 1
      }
    ]
  },
  "apns_failures": [
    {
      "reason": "BadDeviceToken",
      "status": 400,
      "client_type": "ios",
      "count": 1
    }
  ],
  "api": {
    "window_hours": 24,
    "totals": {
      "total": 20,
      "ok": 18,
      "client_error": 2,
      "server_error": 0
    },
    "by_route": [
      {
        "method": "POST",
        "route": "/v1/push/register",
        "status": 400,
        "error_code": "missing_apns_token",
        "count": 1
      }
    ],
    "by_error": [
      {
        "error_code": "missing_apns_token",
        "status": 400,
        "count": 1
      }
    ]
  }
}
```

The response is aggregate-only. It never includes raw request or response
bodies, Authorization headers, IP addresses, raw install IDs, raw device IDs,
APNs tokens, encrypted APNs token material, relay secrets, Home Assistant
tokens, Spotify tokens, prompts, responses or chat history.

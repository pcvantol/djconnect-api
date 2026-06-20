# API Contract

Base URL: `https://api.djconnect.dev`

Auth for all `/v1/*` endpoints:

```http
Authorization: Bearer <DJCONNECT_RELAY_SECRET>
```

HMAC auth is also supported with:

- `x-djconnect-timestamp`: Unix seconds
- `x-djconnect-signature`: `sha256=<hex_hmac_sha256(timestamp + "." + raw_body)>`

## GET /health

Public liveness check.

Response:

```json
{ "ok": true, "service": "djconnect-api" }
```

## POST /v1/push/register

Registers or updates one Apple client device.

Request:

```json
{
  "ha_install_id": "install-id",
  "ha_user_hash": "optional-privacy-safe-user-hash",
  "device_id": "client-generated-stable-device-id",
  "client_type": "ios",
  "apns_token": "hex-token-from-apple",
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

## POST /v1/push/unregister

Disables a registration.

Request:

```json
{
  "ha_install_id": "install-id",
  "device_id": "client-generated-stable-device-id",
  "client_type": "ios",
  "apns_token": "optional-token"
}
```

Response:

```json
{ "ok": true, "disabled": 1 }
```

## POST /v1/push/event

Relays a generic push notification to active registrations for a Home Assistant install.

Request:

```json
{
  "ha_install_id": "install-id",
  "ha_user_hash": "optional-user-hash-filter",
  "event_type": "ask_dj_response",
  "history_revision": "42",
  "client_message_id": "optional-client-message-id",
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

# API Contract

Base URL: `https://api.djconnect.dev`

Production auth uses per-install tokens. HACS integrations must never embed a
global DJConnect secret.

Bootstrap auth is only for trusted operator/admin flows that issue install
tokens:

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

## POST /v1/install/token

Issues a per-install token. This endpoint is protected by bootstrap auth and is
not called by public HACS code with a bundled secret.

Request:

```json
{
  "ha_install_id": "example-ha-install",
  "ha_user_hash": "example-user-hash",
  "label": "example-ha"
}
```

Response:

```json
{
  "ok": true,
  "id": "install-token-id",
  "token": "djci_example-install-token-returned-once",
  "token_hash": "sha256-hex"
}
```

Store the returned token in the Home Assistant config entry storage. The raw
token is returned once and is stored by the API only as a SHA-256 hash.

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

#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-https://api.djconnect.dev}"
HA_INSTALL_ID="example-smoke-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
DEVICE_ID="example-smoke-device-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
CLIENT_TYPE="ios"
APNS_TOKEN="example-smoke-apns-token-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"

if [[ "$-" == *x* ]]; then
  echo "Refusing to run with shell tracing enabled." >&2
  exit 1
fi

if [[ -z "${DJCONNECT_RELAY_SECRET_VALUE:-}" ]]; then
  echo "DJCONNECT_RELAY_SECRET_VALUE is required." >&2
  exit 64
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

require_command curl
require_command node

post_json() {
  local path="$1"
  local body="$2"
  local auth="${3:-}"
  local response_file
  local status_code

  response_file="$(mktemp)"
  if [[ -n "$auth" ]]; then
    status_code="$(curl -sS -o "$response_file" -w '%{http_code}' \
      -X POST "${API_URL}${path}" \
      -H 'Content-Type: application/json' \
      -H "Authorization: Bearer ${auth}" \
      --data "$body")"
  else
    status_code="$(curl -sS -o "$response_file" -w '%{http_code}' \
      -X POST "${API_URL}${path}" \
      -H 'Content-Type: application/json' \
      --data "$body")"
  fi

  if [[ "$status_code" -lt 200 || "$status_code" -ge 300 ]]; then
    echo "Request ${path} failed with HTTP ${status_code}. Response redacted at ${response_file}." >&2
    exit 1
  fi
  printf '%s' "$response_file"
}

json_get() {
  local file="$1"
  local field="$2"
  node -e "const fs=require('fs'); const body=JSON.parse(fs.readFileSync(process.argv[1], 'utf8')); const value=body[process.argv[2]]; if (!value) process.exit(1); process.stdout.write(String(value));" "$file" "$field"
}

echo "Smoke E2E: issuing bootstrap proof for ${HA_INSTALL_ID}"
proof_body="$(node -e '
const body = {
  ha_install_id: process.argv[1],
  integration: "djconnect_hacs",
  integration_version: "example-ci",
  client_type: process.argv[2],
  device_id: process.argv[3],
  pairing_session_id: "example-ci-pairing",
  ttl_seconds: 600,
};
process.stdout.write(JSON.stringify(body));
' "$HA_INSTALL_ID" "$CLIENT_TYPE" "$DEVICE_ID")"
proof_response="$(post_json "/v1/install/bootstrap-proof" "$proof_body" "$DJCONNECT_RELAY_SECRET_VALUE")"
bootstrap_proof="$(json_get "$proof_response" bootstrap_proof)"
rm -f "$proof_response"

echo "Smoke E2E: exchanging proof for install token"
token_body="$(node -e '
const body = {
  ha_install_id: process.argv[1],
  ha_user_hash: "example-user-hash",
  label: "example-ci",
  integration: "djconnect_hacs",
  integration_version: "example-ci",
  client_type: process.argv[2],
  device_id: process.argv[3],
  bootstrap_proof: process.argv[4],
};
process.stdout.write(JSON.stringify(body));
' "$HA_INSTALL_ID" "$CLIENT_TYPE" "$DEVICE_ID" "$bootstrap_proof")"
token_response="$(post_json "/v1/install/token" "$token_body")"
install_token="$(json_get "$token_response" install_token)"
rm -f "$token_response"
unset bootstrap_proof

echo "Smoke E2E: registering example Apple client"
register_body="$(node -e '
const body = {
  ha_install_id: process.argv[1],
  ha_user_hash: "example-user-hash",
  device_id: process.argv[2],
  client_type: process.argv[3],
  apns_token: process.argv[4],
  apns_environment: "sandbox",
  app_bundle_id: "dev.djconnect.ios",
  app_version: "example-ci",
  locale: "en-US",
  categories: ["ask_dj"],
};
process.stdout.write(JSON.stringify(body));
' "$HA_INSTALL_ID" "$DEVICE_ID" "$CLIENT_TYPE" "$APNS_TOKEN")"
register_response="$(post_json "/v1/push/register" "$register_body" "$install_token")"
rm -f "$register_response"

echo "Smoke E2E: sending privacy-safe event"
event_body="$(node -e '
const body = {
  ha_install_id: process.argv[1],
  ha_user_hash: "example-user-hash",
  event_type: "ask_dj_response",
  history_revision: "example-ci",
  client_message_id: "example-ci-message",
  open_target: "history",
  client_types: ["ios"],
};
process.stdout.write(JSON.stringify(body));
' "$HA_INSTALL_ID")"
event_response="$(post_json "/v1/push/event" "$event_body" "$install_token")"
node -e '
const fs=require("fs");
const body=JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (body.matched !== 1 || body.delivered !== 1 || body.failed !== 0) {
  console.error("Unexpected event result:", JSON.stringify({ matched: body.matched, delivered: body.delivered, failed: body.failed }));
  process.exit(1);
}
' "$event_response"
rm -f "$event_response"
unset install_token

echo "Smoke E2E: success"

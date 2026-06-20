#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/provision_cloudflare.sh [options]

Safe by default: this script runs in dry-run mode unless --execute is passed.
It never prints secret values. Do not run with shell tracing (set -x).

Options:
  --execute                 Actually run selected actions. Default is dry-run.
  --all                     Run secrets, remote migration, deploy, domain setup and smoke test.
  --set-secrets             Set APNS_PRIVATE_KEY and DJCONNECT_RELAY_SECRET with Wrangler.
  --migrate                 Apply D1 migrations to the remote djconnect_api database.
  --deploy                  Deploy the Worker with Wrangler.
  --custom-domain           Configure the Worker custom domain through Cloudflare API.
  --smoke-test              GET /health from the configured API URL.
  --apns-private-key-file PATH
                            Local .p8 file to read for APNS_PRIVATE_KEY.
                            Required with --set-secrets.
  --relay-secret-env NAME   Environment variable containing the relay secret.
                            Default: DJCONNECT_RELAY_SECRET_VALUE.
  --account-id ID           Cloudflare account ID. Default: CLOUDFLARE_ACCOUNT_ID.
  --api-token-env NAME      Environment variable containing Cloudflare API token.
                            Default: CLOUDFLARE_API_TOKEN.
  --service NAME            Worker service name. Default: djconnect-api.
  --hostname HOST           Worker custom domain. Default: api.djconnect.dev.
  --api-url URL             Smoke-test URL. Default: https://api.djconnect.dev.
  -h, --help                Show this help.

Examples:
  scripts/provision_cloudflare.sh --all
  scripts/provision_cloudflare.sh --execute --migrate --deploy --smoke-test
  DJCONNECT_RELAY_SECRET_VALUE='...' \
    scripts/provision_cloudflare.sh --execute --set-secrets \
    --apns-private-key-file /secure/path/key.p8
EOF
}

EXECUTE=false
SET_SECRETS=false
MIGRATE=false
DEPLOY=false
CUSTOM_DOMAIN=false
SMOKE_TEST=false
APNS_PRIVATE_KEY_FILE=""
RELAY_SECRET_ENV="DJCONNECT_RELAY_SECRET_VALUE"
ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-}"
API_TOKEN_ENV="CLOUDFLARE_API_TOKEN"
SERVICE_NAME="djconnect-api"
HOSTNAME="api.djconnect.dev"
API_URL="https://api.djconnect.dev"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute)
      EXECUTE=true
      shift
      ;;
    --all)
      SET_SECRETS=true
      MIGRATE=true
      DEPLOY=true
      CUSTOM_DOMAIN=true
      SMOKE_TEST=true
      shift
      ;;
    --set-secrets)
      SET_SECRETS=true
      shift
      ;;
    --migrate)
      MIGRATE=true
      shift
      ;;
    --deploy)
      DEPLOY=true
      shift
      ;;
    --custom-domain)
      CUSTOM_DOMAIN=true
      shift
      ;;
    --smoke-test)
      SMOKE_TEST=true
      shift
      ;;
    --apns-private-key-file)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--apns-private-key-file requires a path." >&2
        exit 64
      fi
      APNS_PRIVATE_KEY_FILE="$2"
      shift 2
      ;;
    --relay-secret-env)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--relay-secret-env requires an environment variable name." >&2
        exit 64
      fi
      RELAY_SECRET_ENV="$2"
      shift 2
      ;;
    --account-id)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--account-id requires a Cloudflare account ID." >&2
        exit 64
      fi
      ACCOUNT_ID="$2"
      shift 2
      ;;
    --api-token-env)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--api-token-env requires an environment variable name." >&2
        exit 64
      fi
      API_TOKEN_ENV="$2"
      shift 2
      ;;
    --service)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--service requires a Worker service name." >&2
        exit 64
      fi
      SERVICE_NAME="$2"
      shift 2
      ;;
    --hostname)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--hostname requires a hostname." >&2
        exit 64
      fi
      HOSTNAME="$2"
      shift 2
      ;;
    --api-url)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "--api-url requires a URL." >&2
        exit 64
      fi
      API_URL="${2%/}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

if [[ ! -f "wrangler.jsonc" || ! -f "package.json" ]]; then
  echo "Run this script from the djconnect-api repository root." >&2
  exit 1
fi

if [[ "$SET_SECRETS" == false && "$MIGRATE" == false && "$DEPLOY" == false && "$CUSTOM_DOMAIN" == false && "$SMOKE_TEST" == false ]]; then
  echo "No actions selected. Use --all or one of --set-secrets, --migrate, --deploy, --custom-domain, --smoke-test." >&2
  exit 64
fi

if [[ "$-" == *x* ]]; then
  echo "Refusing to run with shell tracing enabled because secrets may be handled." >&2
  exit 1
fi

say_action() {
  if [[ "$EXECUTE" == true ]]; then
    echo "+ $*"
  else
    echo "+ dry-run: $*"
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

require_command npx

if [[ "$CUSTOM_DOMAIN" == true ]]; then
  require_command curl
fi

if [[ "$SMOKE_TEST" == true ]]; then
  require_command curl
fi

set_worker_secret_from_file() {
  local name="$1"
  local path="$2"

  if [[ -z "$path" ]]; then
    if [[ "$EXECUTE" == true ]]; then
      echo "--apns-private-key-file is required for --set-secrets." >&2
      exit 64
    fi
    say_action "set Worker secret $name from .p8 file (path required when executing)"
    return
  fi
  if [[ "$path" != *.p8 ]]; then
    echo "APNs private key file should be a .p8 file." >&2
    exit 1
  fi
  if [[ "$EXECUTE" == true && ! -f "$path" ]]; then
    echo "APNs private key file does not exist: $path" >&2
    exit 1
  fi

  say_action "set Worker secret $name from .p8 file (value redacted)"
  if [[ "$EXECUTE" == true ]]; then
    npx wrangler secret put "$name" < "$path" >/dev/null
  fi
}

set_worker_secret_from_env() {
  local name="$1"
  local env_name="$2"
  local value="${!env_name:-}"

  if [[ -z "$value" ]]; then
    if [[ "$EXECUTE" == true ]]; then
      echo "Environment variable $env_name is required for $name." >&2
      exit 64
    fi
    say_action "set Worker secret $name from environment variable $env_name (value required when executing)"
    return
  fi
  if [[ "${#value}" -lt 32 ]]; then
    echo "$env_name must be at least 32 characters." >&2
    exit 1
  fi

  say_action "set Worker secret $name from environment variable $env_name (value redacted)"
  if [[ "$EXECUTE" == true ]]; then
    printf '%s' "$value" | npx wrangler secret put "$name" >/dev/null
  fi
}

configure_custom_domain() {
  local api_token="${!API_TOKEN_ENV:-}"
  local response_file
  local status_code

  if [[ "$EXECUTE" != true ]]; then
    say_action "configure Worker custom domain $HOSTNAME for service $SERVICE_NAME"
    return
  fi

  if [[ -z "$ACCOUNT_ID" ]]; then
    echo "Cloudflare account ID is required. Set CLOUDFLARE_ACCOUNT_ID or pass --account-id." >&2
    exit 64
  fi
  if [[ -z "$api_token" ]]; then
    echo "Cloudflare API token is required. Set $API_TOKEN_ENV or pass --api-token-env." >&2
    exit 64
  fi

  say_action "configure Worker custom domain $HOSTNAME for service $SERVICE_NAME"

  response_file="$(mktemp)"
  status_code="$(
    curl -sS -o "$response_file" -w '%{http_code}' \
      -X PUT "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/domains" \
      -H "Authorization: Bearer ${api_token}" \
      -H "Content-Type: application/json" \
      --data "{\"hostname\":\"${HOSTNAME}\",\"service\":\"${SERVICE_NAME}\",\"environment\":\"production\"}"
  )"

  if [[ "$status_code" -lt 200 || "$status_code" -ge 300 ]]; then
    echo "Cloudflare custom domain API failed with HTTP $status_code." >&2
    echo "Response body is in $response_file. Review it locally; do not paste it publicly if it contains account metadata." >&2
    exit 1
  fi

  rm -f "$response_file"
}

if [[ "$SET_SECRETS" == true ]]; then
  set_worker_secret_from_file "APNS_PRIVATE_KEY" "$APNS_PRIVATE_KEY_FILE"
  set_worker_secret_from_env "DJCONNECT_RELAY_SECRET" "$RELAY_SECRET_ENV"
fi

if [[ "$MIGRATE" == true ]]; then
  say_action "apply remote D1 migrations for djconnect_api"
  if [[ "$EXECUTE" == true ]]; then
    npx wrangler d1 migrations apply djconnect_api --remote
  fi
fi

if [[ "$DEPLOY" == true ]]; then
  say_action "deploy Worker"
  if [[ "$EXECUTE" == true ]]; then
    npm run deploy
  fi
fi

if [[ "$CUSTOM_DOMAIN" == true ]]; then
  configure_custom_domain
fi

if [[ "$SMOKE_TEST" == true ]]; then
  say_action "smoke test ${API_URL}/health"
  if [[ "$EXECUTE" == true ]]; then
    curl -fsS "${API_URL}/health"
    echo
  fi
fi

if [[ "$EXECUTE" != true ]]; then
  echo
  echo "Dry-run complete. Re-run with --execute to perform the selected actions."
fi

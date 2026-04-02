#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_NAME="${VAULT_TRANSIT_KEY_NAME:-camellia}"
POLICY_NAME="${VAULT_TRANSIT_POLICY_NAME:-camellia-transit}"
MOUNT_PATH="${VAULT_TRANSIT_MOUNT:-transit}"

if [[ -z "${VAULT_ADDR:-}" ]]; then
  echo "VAULT_ADDR is required"
  exit 1
fi

if [[ -z "${VAULT_TOKEN:-}" ]]; then
  echo "VAULT_TOKEN is required"
  exit 1
fi

VAULT_BIN="${VAULT_BIN:-vault}"

if ! command -v "$VAULT_BIN" >/dev/null 2>&1; then
  echo "vault CLI not found"
  exit 1
fi

tmp_policy="$(mktemp)"
trap 'rm -f "$tmp_policy"' EXIT

cat > "$tmp_policy" <<EOF
path "${MOUNT_PATH}/encrypt/${KEY_NAME}" {
  capabilities = ["update"]
}

path "${MOUNT_PATH}/decrypt/${KEY_NAME}" {
  capabilities = ["update"]
}
EOF

if ! "$VAULT_BIN" secrets list -format=json | grep -q "\"${MOUNT_PATH}/\""; then
  "$VAULT_BIN" secrets enable -path="${MOUNT_PATH}" transit
fi

if ! "$VAULT_BIN" read -format=json "${MOUNT_PATH}/keys/${KEY_NAME}" >/dev/null 2>&1; then
  "$VAULT_BIN" write -f "${MOUNT_PATH}/keys/${KEY_NAME}"
fi

"$VAULT_BIN" policy write "$POLICY_NAME" "$tmp_policy" >/dev/null
APP_TOKEN="$("$VAULT_BIN" token create -policy="$POLICY_NAME" -field=token)"

printf '\nVault Transit configured.\n\n'
printf 'Use these values in Vercel:\n'
printf 'KMS_PROVIDER=transit\n'
printf 'VAULT_ADDR=%s\n' "$VAULT_ADDR"
printf 'VAULT_TOKEN=%s\n' "$APP_TOKEN"
printf 'VAULT_TRANSIT_KEY_NAME=%s\n' "$KEY_NAME"
printf 'VAULT_TRANSIT_MOUNT=%s\n' "$MOUNT_PATH"

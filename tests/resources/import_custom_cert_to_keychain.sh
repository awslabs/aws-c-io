#!/usr/bin/env bash
set -euo pipefail

KEYCHAIN_PATH="${RUNNER_TEMP:-/tmp}/custom-keychain.keychain-db"

# The password is needed only during the keychain creation, so use some random-generated value.
KEYCHAIN_PASSWORD=$(openssl rand -base64 32)

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
# Make the new keychain searchable.
security list-keychains -d user -s "$KEYCHAIN_PATH"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
#security add-trusted-cert -r trustRoot -k "$KEYCHAIN_PATH" "$SCRIPT_DIR/mtls_server_root_ca.pem.crt"
security import "$SCRIPT_DIR/mtls_server_root_ca.pem.crt" -k "$KEYCHAIN_PATH"

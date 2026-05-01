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

security import "$SCRIPT_DIR/mtls_server_root_ca.pem.crt" -k "$KEYCHAIN_PATH"
sudo security trust-settings-import -d "$SCRIPT_DIR/mtls_server_root_ca_trust_settings.plist"

# Import the untrusted server root CA into the keychain without adding trust settings, so it remains untrusted.
security import "$SCRIPT_DIR/mtls_untrusted_server_root_ca.pem.crt" -k "$KEYCHAIN_PATH"

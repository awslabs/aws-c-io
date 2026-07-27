# Test Resources

## generateCerts.sh

Regenerates all test certificates used by unit tests (TLS connections between localhost server and client). Run this
script when certificates expire.

Generated files include RSA/EC self-signed certs, a CA-signed server cert chain, mTLS root CAs with server/device certs,
an untrusted server CA, and the macOS trust settings plist for `mtls_server_root_ca`. See the script header for the full list.

## import_custom_cert_to_keychain.sh

macOS-only script used in CI to set up a temporary keychain with test certificates for keychain-related tests.
It creates a keychain, imports a trusted and an untrusted CA certificate, and configures trust settings
so that tests can verify correct behavior for both trusted and untrusted certificates.

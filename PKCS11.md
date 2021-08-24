# PKCS#11 tests

To run the PKCS#11 tests, configure cmake with: `-DENABLE_PKCS11_TESTS=ON`

and set the following environment variables:

```
TEST_PKCS11_LIB = <path-to-shared-lib>
TEST_PKCS11_TOKEN_LABEL = <token-label>
TEST_PKCS11_PIN = <pin-for-logging-into-token>
TEST_PKCS11_PKEY_LABEL = <private-key-label>
TEST_PKCS11_CERT_FILE = <path-to-PEM-encoded-certificate>
TEST_PKCS11_CA_FILE = <path-to-PEM-encoded-CA-file-needed-to-trust-certificate>
```

## The suggested way to set up your machine
1)  Install [SoftHSM2](https://www.opendnssec.org/softhsm/) via brew / apt / apt-get / yum:
    ```
    > apt install softhsm
    ```

    Check that it's working:
    ```
    > softhsm2-util --show-slots
    ```

    If this spits out an error message, create a config file:
    *   Default location: `~/.config/softhsm2/softhsm2.conf`
    *   This file must specify token dir, default value is:
        ```
        directories.tokendir = /usr/local/var/lib/softhsm/tokens/
        ```

2)  Create token and private key.

    You can use any values for the labels, pin, key, cert, CA etc.
    Here are copy-paste friendly commands for using files available in this repo.
    ```
    > softhsm2-util --init-token --free --label my-test-token --pin 0000 --so-pin 0000
    ```

    Note which slot the token ended up in

    ```
    > softhsm2-util --import tests/resources/unittests.p8 --slot <slot-with-token> --label my-test-key --id BEEFCAFE --pin 0000
    ```

3)  Set env vars like so:
    ```
    TEST_PKCS11_LIB = <path to libsofthsm2.so>
    TEST_PKCS11_TOKEN_LABEL = my-test-token
    TEST_PKCS11_PIN = 0000
    TEST_PKCS11_PKEY_LABEL = my-test-key
    TEST_PKCS11_CERT_FILE = <path to aws-c-io>/tests/resources/unittests.crt
    TEST_PKCS11_CA_FILE = <path to aws-c-io>/tests/resources/unittests.crt
    ```

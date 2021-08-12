/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/private/pkcs11_private.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/testing/aws_test_harness.h>

/**
 * To run these tests, configure cmake with: -DENABLE_PKCS11_TESTS=ON
 * and set the following environment variables:
 *
 * TEST_PKCS11_LIB = <path to shared lib>
 *      common paths to softhsm are:
 *      /usr/lib/softhsm2/libsofthsm2.so
 *      /usr/lib64/libsofthsm2.so
 *      /usr/local/lib/softhsm/libsofthsm2.so
 *
 * TEST_PKCS11_TOKEN_LABEL = <token label>
 * TEST_PKCS11_PIN = <pin for logging into token>
 * TEST_PKCS11_PKEY_LABEL = <private key label>
 * TEST_PKCS11_CERT_FILE = <path to PEM-encoded certificate>
 * TEST_PKCS11_CA_FILE = <path to PEM-encoded CA file needed to trust certificate>
 *      If omitted, the system's default trust store is used.
 *
 * The suggested way to set up your local machine is like so:
 * 1)   Install SoftHSM2 via brew/apt/apt-get/yum:
 *      > brew install softhsm
 *
 * 2)   Ensure if it's working:
 *      > softhsm2-util --show-slots
 *
 *      If this spits out an error message, create a config file:
 *      Default location: ~/.config/softhsm2/softhsm2.conf
 *      Contents must specify token dir, default value is:
 *          directories.tokendir = /usr/local/var/lib/softhsm/tokens/
 *
 * 3)   Create token and private key.
 *      You could any labels/pin and any key/cert/ca with the tests.
 *      These commands show us using files from source control and specific labels/pin:
 *
 *      > softhsm2-util --init-token --free --label my-test-token --pin 0000 --so-pin 0000
 *      look at slot that the token ended up in
 *
 *      > softhsm2-util --import tests/resources/unittests.p8 --slot <slot-from-above> \
 *        --label my-test-key --id BEEFCAFE --pin 0000
 *
 * 4)   Set env vars listed above
 *
 * CI machines running aws-crt-builder will be set up by pkcs11_test_setup.py.
 * But this script is made for use with aws-crt-builder, so it's tough to run standalone.
 */

AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_LIB, "TEST_PKCS11_LIB");

/* Singleton that stores env-var values */
struct pkcs11_tester {
    struct aws_string *filepath;
};
static struct pkcs11_tester s_pkcs11_tester;

static void s_pkcs11_tester_clean_up(void) {
    aws_string_destroy(s_pkcs11_tester.filepath);
    aws_io_library_clean_up();
}

/* Read env-vars */
static int s_pkcs11_tester_init(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    const struct aws_string *env_var = TEST_PKCS11_LIB;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.filepath);
    if (s_pkcs11_tester.filepath == NULL) {
        goto missing;
    }

    return AWS_OP_SUCCESS;

missing:
    printf("Missing required env-var '%s'\n", aws_string_c_str(env_var));
    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

/* Simplest test: Loads and unloads library, calling C_Initialize() and C_Finalize() */
static int s_test_pkcs11_lib_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Clean up */
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_initialize, s_test_pkcs11_lib_initialize)

/* Test that we can use the `omit_initialize` option to have the library loaded multiple times */
static int s_test_pkcs11_lib_omit_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    struct aws_pkcs11_lib_options options_normal = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };

    struct aws_pkcs11_lib_options options_omit_initialize = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
        .omit_initialize = true,
    };

    /* First test that we fail gracefully if we omit_initialize, but no one else has initialized it yet either */
    struct aws_pkcs11_lib *pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_IO_PKCS11_ERROR, aws_last_error());

    /* Next test that we can load the library twice by using omit_initialize the second time we load it */
    struct aws_pkcs11_lib *pkcs11_lib_1 = aws_pkcs11_lib_new(allocator, &options_normal);
    ASSERT_NOT_NULL(pkcs11_lib_1);

    struct aws_pkcs11_lib *pkcs11_lib_2 = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NOT_NULL(pkcs11_lib_2);

    /* Next test that omit_initialize is required if someone else already initialized the library */
    pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_normal);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_IO_PKCS11_ERROR, aws_last_error());

    /* Clean up */
    aws_pkcs11_lib_release(pkcs11_lib_2);
    aws_pkcs11_lib_release(pkcs11_lib_1);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_omit_initialize, s_test_pkcs11_lib_omit_initialize)

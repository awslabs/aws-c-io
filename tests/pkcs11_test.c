/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * See PKCS11.md for instructions on running these tests
 */

#include <aws/io/pkcs11.h>
#include <aws/io/private/pkcs11_private.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/testing/aws_test_harness.h>

AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_LIB, "TEST_PKCS11_LIB");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_TOKEN_LABEL, "TEST_PKCS11_TOKEN_LABEL");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_PIN, "TEST_PKCS11_PIN");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_PKEY_LABEL, "TEST_PKCS11_PKEY_LABEL");

/* Singleton that stores env-var values */
struct pkcs11_tester {
    struct aws_string *filepath;
    struct aws_string *token_label;
    struct aws_string *pin;
    struct aws_string *pkey_label;
};
static struct pkcs11_tester s_pkcs11_tester;

static void s_pkcs11_tester_clean_up(void) {
    aws_string_destroy(s_pkcs11_tester.filepath);
    aws_string_destroy(s_pkcs11_tester.token_label);
    aws_string_destroy(s_pkcs11_tester.pin);
    aws_string_destroy(s_pkcs11_tester.pkey_label);
    aws_io_library_clean_up();
}

/* Read env-vars.
 * Raise an error if any necessary ones are missing */
static int s_pkcs11_tester_init(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    const struct aws_string *env_var = TEST_PKCS11_LIB;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.filepath);
    if (s_pkcs11_tester.filepath == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_TOKEN_LABEL;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.token_label);
    if (s_pkcs11_tester.token_label == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_PIN;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.pin);
    if (s_pkcs11_tester.pin == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_PKEY_LABEL;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.pkey_label);
    if (s_pkcs11_tester.pkey_label == NULL) {
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

static int s_test_pkcs11_find_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Find token slot*/
    CK_SLOT_ID slot_id;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, s_pkcs11_tester.token_label, &slot_id /*out*/));

    /* Open session */
    CK_SESSION_HANDLE session_handle;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, slot_id, &session_handle /*out*/));

    /* Login user */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_handle, s_pkcs11_tester.pin));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle;
    CK_KEY_TYPE pkey_type;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib, session_handle, s_pkcs11_tester.pkey_label, &pkey_handle, &pkey_type));

    /* Clean up */
    aws_pkcs11_lib_close_session(pkcs11_lib, session_handle);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key, s_test_pkcs11_find_private_key)

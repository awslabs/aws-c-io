/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/private/pkcs11_private.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/testing/aws_test_harness.h>

/* Environment variables that must be set for these tests (otherwise the tests are skipped) */
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

/* Read env-vars.
 * Raises an error if env-vars not set, and the test should be skipped */
static int s_pkcs11_tester_init_or_skip(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    const struct aws_string *env_var = TEST_PKCS11_LIB;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.filepath);
    if (s_pkcs11_tester.filepath == NULL) {
        goto skip;
    }

    return AWS_OP_SUCCESS;

skip:
    printf("Skipping test because '%s' env-var not found\n", aws_string_c_str(env_var));
    s_pkcs11_tester_clean_up();
    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

static int s_test_pkcs11_lib_new(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    if (s_pkcs11_tester_init_or_skip(allocator) != AWS_OP_SUCCESS) {
        return AWS_OP_SUCCESS;
    }

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
AWS_TEST_CASE(pkcs11_lib_new, s_test_pkcs11_lib_new)

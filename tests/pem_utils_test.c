/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/string.h>
#include <aws/io/private/pem_utils.h>

#include <aws/testing/aws_test_harness.h>

static int s_check_clean_pem_result(
    struct aws_byte_cursor dirty_pem,
    struct aws_byte_cursor expected_clean_pem,
    struct aws_allocator *allocator) {
    struct aws_byte_buf pem_buf;
    ASSERT_SUCCESS(aws_byte_buf_init_copy_from_cursor(&pem_buf, allocator, dirty_pem));
    ASSERT_SUCCESS(aws_sanitize_pem(&pem_buf, allocator));
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected_clean_pem, &pem_buf));
    aws_byte_buf_clean_up(&pem_buf);
    return AWS_OP_SUCCESS;
}

static int s_test_pem_util_comments_around_pem_object(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* comments around pem object will be removed */
    struct aws_byte_cursor dirty_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("# comments\r\n"
                                                                             "-----BEGIN CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "-----END CERTIFICATE-----\n"
                                                                             "# another comments\r\n"
                                                                             "-----BEGIN CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "-----END CERTIFICATE-----\n"
                                                                             "# final comments\r\n");

    struct aws_byte_cursor expected_clean_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n"
                                                                                      "-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n");

    return s_check_clean_pem_result(dirty_pem, expected_clean_pem, allocator);
}

AWS_TEST_CASE(test_pem_util_comments_around_pem_object, s_test_pem_util_comments_around_pem_object);

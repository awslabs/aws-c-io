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
    struct aws_string *clean_pem = aws_clean_up_pem(dirty_pem, allocator);
    ASSERT_TRUE(aws_string_eq_byte_cursor(clean_pem, &expected_clean_pem));
    aws_string_destroy(clean_pem);
    return AWS_OP_SUCCESS;
}

static int s_test_pem_util_comments_around_pem_object(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* comments around pem object will be removed */
    struct aws_byte_cursor dirty_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("# comments\r\n"
                                                                             "-----BEGIN CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "-----END CERTIFICATE-----\n"
                                                                             "# shake shack\r\n"
                                                                             "-----BEGIN CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "-----END CERTIFICATE-----\n"
                                                                             "# in & out\r\n");

    struct aws_byte_cursor expected_clean_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n"
                                                                                      "-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n");

    return s_check_clean_pem_result(dirty_pem, expected_clean_pem, allocator);
}

AWS_TEST_CASE(test_pem_util_comments_around_pem_object, s_test_pem_util_comments_around_pem_object);

static int s_test_pem_util_ensure_dashes_num(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* The number of dashes "-" on the BEGIN and END lines are exactly 5 dashes */
    struct aws_byte_cursor dirty_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-------BEGIN CERTIFICATE---------\n"
                                                                             "CERTIFICATES\n"
                                                                             "----END CERTIFICATE--------\n"
                                                                             "--BEGIN CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "-----END CERTIFICATE--\n");

    struct aws_byte_cursor expected_clean_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n"
                                                                                      "-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n");

    return s_check_clean_pem_result(dirty_pem, expected_clean_pem, allocator);
}

AWS_TEST_CASE(test_pem_util_ensure_dashes_num, s_test_pem_util_ensure_dashes_num);

static int s_test_pem_util_white_space_formatting(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /**
     * - Merge consecutive spaces into a single space (Eg "BEGIN     CERTIFICATE", will become "BEGIN CERTIFICATE")
     * - Remove any spaces next to dashes (Eg "----- BEGIN" will become "-----BEGIN")
     */
    struct aws_byte_cursor dirty_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----  BEGIN     CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "-----END   CERTIFICATE-----\n"
                                                                             "-----BEGIN  CERTIFICATE-----\n"
                                                                             "CERTIFICATES\n"
                                                                             "----- END CERTIFICATE-----\n");

    struct aws_byte_cursor expected_clean_pem = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n"
                                                                                      "-----BEGIN CERTIFICATE-----\n"
                                                                                      "CERTIFICATES\n"
                                                                                      "-----END CERTIFICATE-----\n");

    return s_check_clean_pem_result(dirty_pem, expected_clean_pem, allocator);
}

AWS_TEST_CASE(test_pem_util_white_space_formatting, s_test_pem_util_white_space_formatting);

static int s_test_pem_util_content_formatting(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /**
     * - Only whitespace is a single newline every 64 chars
     * - All lines exactly 64 Characters long except for the last line.
     * - Remove any invalid character.
     */
    struct aws_byte_cursor dirty_pem =
        AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                              "MIIDzjCCArY      CCQCoztOER4pOk\r\n"
                                              "zANBgkqhkiG9w0BAQs FADCBqDELMAkGA1UEBhMC\r\n"
                                              "VVMxEzARBgNVBAgM\n"
                                              "Cldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNV"
                                              "BAoMF0FtYXpvbiBXZWIgU2VydmljZXMgSW5jMRswGQ"
                                              "-----END CERTIFICATE-----\n"
                                              "-----BEGIN CERTIFICATE-----\n"
                                              "CERTIFICATES\n"
                                              "-----END CERTIFICATE-----\n");

    struct aws_byte_cursor expected_clean_pem =
        AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                              "MIIDzjCCArYCCQCoztOER4pOkzANBgkqhkiG9w0BAQsFADCBqDELMAkGA1UEBhMC\n"
                                              "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNV\n"
                                              "BAoMF0FtYXpvbiBXZWIgU2VydmljZXMgSW5jMRswGQ\n"
                                              "-----END CERTIFICATE-----\n"
                                              "-----BEGIN CERTIFICATE-----\n"
                                              "CERTIFICATES\n"
                                              "-----END CERTIFICATE-----\n");

    return s_check_clean_pem_result(dirty_pem, expected_clean_pem, allocator);
}

AWS_TEST_CASE(test_pem_util_content_formatting, s_test_pem_util_content_formatting);

static int s_test_pem_util_invalid_character(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /**
     * - Remove any invalid character.
     */
    struct aws_byte_cursor dirty_pem =
        AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                              "MIIDzjCCArY      CCQCoztOER4pOk\r\n"
                                              "zANBgkqhk#$#%^$&*iG9w0BAQs FADCBqDELMAkGA1UEBhMC\r\n"
                                              "VVMxEzARBgNVBAgM\n"
                                              "Cldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNV"
                                              "BAoMF0FtYXpvb()!@~`iBXZWIgU2VydmljZXMgSW5jMRswGQ"
                                              "-----END CERTIFICATE-----\n"
                                              "-----BEGIN CERTIFICATE-----\n"
                                              "CERTIFICATES\n"
                                              "-----END CERTIFICATE-----\n");

    struct aws_byte_cursor expected_clean_pem =
        AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN CERTIFICATE-----\n"
                                              "MIIDzjCCArYCCQCoztOER4pOkzANBgkqhkiG9w0BAQsFADCBqDELMAkGA1UEBhMC\n"
                                              "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNV\n"
                                              "BAoMF0FtYXpvbiBXZWIgU2VydmljZXMgSW5jMRswGQ\n"
                                              "-----END CERTIFICATE-----\n"
                                              "-----BEGIN CERTIFICATE-----\n"
                                              "CERTIFICATES\n"
                                              "-----END CERTIFICATE-----\n");

    return s_check_clean_pem_result(dirty_pem, expected_clean_pem, allocator);
}

AWS_TEST_CASE(test_pem_util_invalid_character, s_test_pem_util_invalid_character);

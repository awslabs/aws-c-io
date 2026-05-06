/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/socks5.h>

#include <aws/io/private/socks5_impl.h>
#include <aws/testing/aws_test_harness.h>

static struct aws_byte_cursor s_aws_byte_cursor_advance_clipped(struct aws_byte_cursor *cursor, size_t len) {
    size_t to_advance = aws_min_size(len, cursor->len);
    if (to_advance == 0) {
        struct aws_byte_cursor rv = {
            .ptr = NULL,
            .len = 0,
        };

        return rv;
    }

    return aws_byte_cursor_advance(cursor, to_advance);
}

static int s_socks5_negotiation_no_auth_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    struct aws_socks5_proxy_negotiation_strategy_instance *instance =
        aws_socks5_proxy_negotiation_strategy_new_instance(strategy);
    aws_socks5_proxy_negotiation_strategy_instance_destroy(instance);

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_negotiation_no_auth_create_destroy, s_socks5_negotiation_no_auth_create_destroy_fn)

static int s_do_get_auth_methods_test(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_allocator *allocator,
    uint8_t expected_method_id) {
    struct aws_array_list methods;
    aws_array_list_init_dynamic(&methods, allocator, 1, sizeof(uint8_t));

    ASSERT_SUCCESS(aws_socks5_proxy_negotiation_strategy_instance_get_auth_methods(instance, &methods));
    ASSERT_INT_EQUALS(aws_array_list_length(&methods), 1);

    uint8_t method = 0xFF;
    ASSERT_SUCCESS(aws_array_list_get_at(&methods, &method, 0));
    ASSERT_INT_EQUALS(0, method);

    aws_array_list_clean_up(&methods);

    return AWS_OP_SUCCESS;
}

static int s_socks5_negotiation_no_auth_get_method_ids_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    struct aws_socks5_proxy_negotiation_strategy_instance *instance =
        aws_socks5_proxy_negotiation_strategy_new_instance(strategy);

    ASSERT_SUCCESS(s_do_get_auth_methods_test(instance, allocator, 0));

    aws_socks5_proxy_negotiation_strategy_instance_destroy(instance);

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_negotiation_no_auth_get_method_ids, s_socks5_negotiation_no_auth_get_method_ids_fn)

struct auth_negotiation_test_context {
    struct aws_byte_buf *output_buffer;
    struct aws_byte_cursor *input_cursor;
    struct aws_socks5_negotiation_context *negotiation_step_context;
    size_t chunk_length;
    int expected_final_error_code;
};

static int s_verify_negotiation(void *verify_context) {
    struct auth_negotiation_test_context *context = verify_context;

    ASSERT_INT_EQUALS(0, context->output_buffer->len);                  // nothing was written
    ASSERT_INT_EQUALS(0, context->negotiation_step_context->data->len); // used all data

    if (context->input_cursor->len > 0) {
        ASSERT_INT_EQUALS(AWS_S5PS_IN_PROGRESS, context->negotiation_step_context->status);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, context->negotiation_step_context->error_code);
    } else {
        if (context->expected_final_error_code == AWS_ERROR_SUCCESS) {
            ASSERT_INT_EQUALS(AWS_S5PS_SUCCESS, context->negotiation_step_context->status);
        } else {
            ASSERT_INT_EQUALS(AWS_S5PS_FAILURE, context->negotiation_step_context->status);
        }

        ASSERT_INT_EQUALS(context->expected_final_error_code, context->negotiation_step_context->error_code);
    }

    return AWS_OP_SUCCESS;
}

static int s_do_first_phase_auth_negotiation_test(
    struct aws_socks5_proxy_negotiation_strategy *strategy,
    uint8_t *input_data,
    size_t input_length,
    int expected_error_code,
    int (*verify_negotiation_fn)(void *)) {
    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_array(input_data, input_length);
    struct aws_byte_buf input_buffer;
    aws_byte_buf_init_copy_from_cursor(&input_buffer, strategy->allocator, input_cursor);

    struct aws_byte_buf output_buffer;
    aws_byte_buf_init(&output_buffer, input_buffer.allocator, 256);

    for (size_t i = 1; i <= input_buffer.len; ++i) {
        struct aws_socks5_proxy_negotiation_strategy_instance *instance =
            aws_socks5_proxy_negotiation_strategy_new_instance(strategy);

        struct aws_byte_cursor input_cursor = aws_byte_cursor_from_buf(&input_buffer);
        struct aws_byte_cursor chunk_cursor = s_aws_byte_cursor_advance_clipped(&input_cursor, i);

        while (chunk_cursor.len > 0) {
            struct aws_socks5_negotiation_context context;
            AWS_ZERO_STRUCT(context);
            context.data = &chunk_cursor;
            context.to_write = &output_buffer;

            aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(instance, &context);

            struct auth_negotiation_test_context test_context = {
                .output_buffer = &output_buffer,
                .input_cursor = &input_cursor,
                .negotiation_step_context = &context,
                .chunk_length = i,
                .expected_final_error_code = expected_error_code,
            };

            ASSERT_SUCCESS(verify_negotiation_fn(&test_context));

            chunk_cursor = s_aws_byte_cursor_advance_clipped(&input_cursor, i);
            aws_byte_buf_reset(&output_buffer, false);
        }

        aws_socks5_proxy_negotiation_strategy_instance_destroy(instance);
    }

    aws_byte_buf_clean_up(&output_buffer);
    aws_byte_buf_clean_up(&input_buffer);

    return AWS_OP_SUCCESS;
}

static int s_socks5_negotiation_no_auth_negotiate_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    uint8_t input_data[] = {0x05, 0x00};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy, input_data, AWS_ARRAY_SIZE(input_data), AWS_ERROR_SUCCESS, s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_negotiation_no_auth_negotiate_success, s_socks5_negotiation_no_auth_negotiate_success_fn)

static int s_socks5_negotiation_no_auth_negotiate_failure_socks_version_mismatch_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    uint8_t input_data[] = {0x04, 0x00};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy,
        input_data,
        AWS_ARRAY_SIZE(input_data),
        AWS_IO_SOCKS5_PROTOCOL_VERSION_MISMATCH,
        s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_no_auth_negotiate_failure_socks_version_mismatch,
    s_socks5_negotiation_no_auth_negotiate_failure_socks_version_mismatch_fn)

static int s_socks5_negotiation_no_auth_negotiate_failure_method_id_mismatch_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    uint8_t input_data[] = {0x05, 0x01};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy, input_data, AWS_ARRAY_SIZE(input_data), AWS_IO_SOCKS5_UNEXPECTED_METHOD_ID, s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_no_auth_negotiate_failure_method_id_mismatch,
    s_socks5_negotiation_no_auth_negotiate_failure_method_id_mismatch_fn)

static int s_socks5_negotiation_no_auth_negotiate_failure_no_acceptable_method_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    uint8_t input_data[] = {0x05, 0xFF};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy, input_data, AWS_ARRAY_SIZE(input_data), AWS_IO_SOCKS5_NO_ACCEPTABLE_METHODS, s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_no_auth_negotiate_failure_no_acceptable_method,
    s_socks5_negotiation_no_auth_negotiate_failure_no_acceptable_method_fn)

static struct aws_socks5_proxy_negotiation_strategy *s_create_basic_auth_strategy(struct aws_allocator *allocator) {
    struct aws_socks5_proxy_negotiation_basic_auth_options options = {
        .username = aws_byte_cursor_from_c_str("sponge"), .password = aws_byte_cursor_from_c_str("bob")};

    return aws_socks5_proxy_negotiation_strategy_new_basic_auth(allocator, &options);
}

static int s_socks5_negotiation_basic_auth_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    struct aws_socks5_proxy_negotiation_strategy_instance *instance =
        aws_socks5_proxy_negotiation_strategy_new_instance(strategy);
    aws_socks5_proxy_negotiation_strategy_instance_destroy(instance);

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_negotiation_basic_auth_create_destroy, s_socks5_negotiation_basic_auth_create_destroy_fn)

static int s_socks5_negotiation_basic_auth_get_method_ids_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);

    struct aws_socks5_proxy_negotiation_strategy_instance *instance =
        aws_socks5_proxy_negotiation_strategy_new_instance(strategy);

    ASSERT_SUCCESS(s_do_get_auth_methods_test(instance, allocator, 2));

    aws_socks5_proxy_negotiation_strategy_instance_destroy(instance);

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_negotiation_basic_auth_get_method_ids, s_socks5_negotiation_basic_auth_get_method_ids_fn)

static int s_socks5_negotiation_basic_auth_negotiate_failure_socks_version_mismatch_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    uint8_t input_data[] = {0x04, 0x00};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy,
        input_data,
        AWS_ARRAY_SIZE(input_data),
        AWS_IO_SOCKS5_PROTOCOL_VERSION_MISMATCH,
        s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_basic_auth_negotiate_failure_socks_version_mismatch,
    s_socks5_negotiation_basic_auth_negotiate_failure_socks_version_mismatch_fn)

static int s_socks5_negotiation_basic_auth_negotiate_failure_method_id_mismatch_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    uint8_t input_data[] = {0x05, 0x01};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy, input_data, AWS_ARRAY_SIZE(input_data), AWS_IO_SOCKS5_UNEXPECTED_METHOD_ID, s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_basic_auth_negotiate_failure_method_id_mismatch,
    s_socks5_negotiation_basic_auth_negotiate_failure_method_id_mismatch_fn)

static int s_socks5_negotiation_basic_auth_negotiate_failure_no_acceptable_method_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    uint8_t input_data[] = {0x05, 0xFF};
    ASSERT_SUCCESS(s_do_first_phase_auth_negotiation_test(
        strategy, input_data, AWS_ARRAY_SIZE(input_data), AWS_IO_SOCKS5_NO_ACCEPTABLE_METHODS, s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_basic_auth_negotiate_failure_no_acceptable_method,
    s_socks5_negotiation_basic_auth_negotiate_failure_no_acceptable_method_fn)

struct second_phase_negotiation_test_context {
    struct aws_byte_buf *output_buffer;
    struct aws_byte_cursor *input_cursor;
    struct aws_socks5_negotiation_context *negotiation_step_context;
    size_t chunk_length;
};

static const size_t BASIC_AUTH_USER_PASS_REQUEST_LENGTH =
    12; // 1 version byte + 1 length byte + "sponge".len + 1 length byte + "bob".length

static int s_do_second_phase_auth_negotiation_test(
    struct aws_socks5_proxy_negotiation_strategy *strategy,
    uint8_t *phase_one_input_data,
    size_t phase_one_length,
    uint8_t *phase_two_input_data,
    size_t phase_two_length,
    int expected_final_error_code,
    int (*verify_negotiation_fn)(void *)) {
    struct aws_byte_buf phase_one_input_buffer;
    struct aws_byte_cursor phase_one_input_cursor = aws_byte_cursor_from_array(phase_one_input_data, phase_one_length);
    aws_byte_buf_init_copy_from_cursor(&phase_one_input_buffer, strategy->allocator, phase_one_input_cursor);

    struct aws_byte_buf phase_two_input_buffer;
    struct aws_byte_cursor phase_two_input_cursor = aws_byte_cursor_from_array(phase_two_input_data, phase_two_length);
    aws_byte_buf_init_copy_from_cursor(&phase_two_input_buffer, strategy->allocator, phase_two_input_cursor);

    for (size_t i = 1; i <= phase_one_input_buffer.len; ++i) {
        for (size_t j = 1; j <= phase_two_input_buffer.len; ++j) {
            for (size_t k = 1; k <= BASIC_AUTH_USER_PASS_REQUEST_LENGTH; ++k) {
                struct aws_byte_buf output_buffer;
                aws_byte_buf_init(&output_buffer, strategy->allocator, k);

                struct aws_socks5_proxy_negotiation_strategy_instance *instance =
                    aws_socks5_proxy_negotiation_strategy_new_instance(strategy);

                struct aws_byte_cursor input_cursor = aws_byte_cursor_from_buf(&phase_one_input_buffer);
                struct aws_byte_cursor chunk_cursor = s_aws_byte_cursor_advance_clipped(&input_cursor, i);

                struct aws_socks5_negotiation_context context;
                AWS_ZERO_STRUCT(context);

                while (chunk_cursor.len > 0) {
                    context.data = &chunk_cursor;
                    context.to_write = &output_buffer;

                    aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(instance, &context);

                    ASSERT_INT_EQUALS(AWS_S5PS_IN_PROGRESS, context.status);

                    chunk_cursor = s_aws_byte_cursor_advance_clipped(&input_cursor, i);
                }

                struct aws_byte_buf request_buffer;
                aws_byte_buf_init(&request_buffer, strategy->allocator, 256);

                while (request_buffer.len != BASIC_AUTH_USER_PASS_REQUEST_LENGTH) {
                    struct aws_byte_cursor request_cursor = aws_byte_cursor_from_buf(&output_buffer);
                    ASSERT_SUCCESS(aws_byte_buf_append_dynamic(&request_buffer, &request_cursor));

                    aws_byte_buf_reset(&output_buffer, false);
                    context.data = NULL;

                    aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(instance, &context);
                    ASSERT_INT_EQUALS(AWS_S5PS_IN_PROGRESS, context.status);
                }

                input_cursor = aws_byte_cursor_from_buf(&phase_two_input_buffer);
                chunk_cursor = s_aws_byte_cursor_advance_clipped(&input_cursor, j);

                AWS_ZERO_STRUCT(context);

                while (chunk_cursor.len > 0) {
                    context.data = &chunk_cursor;
                    context.to_write = &output_buffer;

                    aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(instance, &context);

                    struct auth_negotiation_test_context test_context = {
                        .output_buffer = &output_buffer,
                        .input_cursor = &input_cursor,
                        .negotiation_step_context = &context,
                        .chunk_length = j,
                        .expected_final_error_code = expected_final_error_code};

                    ASSERT_SUCCESS(verify_negotiation_fn(&test_context));

                    chunk_cursor = s_aws_byte_cursor_advance_clipped(&input_cursor, j);
                }

                aws_socks5_proxy_negotiation_strategy_instance_destroy(instance);

                aws_byte_buf_clean_up(&output_buffer);
                aws_byte_buf_clean_up(&request_buffer);
            }
        }
    }

    aws_byte_buf_clean_up(&phase_one_input_buffer);
    aws_byte_buf_clean_up(&phase_two_input_buffer);

    return AWS_OP_SUCCESS;
}

static int s_socks5_negotiation_basic_auth_negotiate_failure_rejected_username_password_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    uint8_t input_data1[] = {0x05, 0x02};
    uint8_t input_data2[] = {0x01, 0x01};
    ASSERT_SUCCESS(s_do_second_phase_auth_negotiation_test(
        strategy,
        input_data1,
        AWS_ARRAY_SIZE(input_data1),
        input_data2,
        AWS_ARRAY_SIZE(input_data2),
        AWS_IO_SOCKS5_SUBNEGOTIATION_REJECTED,
        s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_basic_auth_negotiate_failure_rejected_username_password,
    s_socks5_negotiation_basic_auth_negotiate_failure_rejected_username_password_fn)

static int s_socks5_negotiation_basic_auth_negotiate_failure_subneg_version_mismatch_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    uint8_t input_data1[] = {0x05, 0x02};
    uint8_t input_data2[] = {0x02, 0x01};
    ASSERT_SUCCESS(s_do_second_phase_auth_negotiation_test(
        strategy,
        input_data1,
        AWS_ARRAY_SIZE(input_data1),
        input_data2,
        AWS_ARRAY_SIZE(input_data2),
        AWS_IO_SOCKS5_SUBNEGOTIATION_VERSION_MISMATCH,
        s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_negotiation_basic_auth_negotiate_failure_subneg_version_mismatch,
    s_socks5_negotiation_basic_auth_negotiate_failure_subneg_version_mismatch_fn)

static int s_socks5_negotiation_basic_auth_negotiate_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    uint8_t input_data1[] = {0x05, 0x02};
    uint8_t input_data2[] = {0x01, 0x00};
    ASSERT_SUCCESS(s_do_second_phase_auth_negotiation_test(
        strategy,
        input_data1,
        AWS_ARRAY_SIZE(input_data1),
        input_data2,
        AWS_ARRAY_SIZE(input_data2),
        AWS_ERROR_SUCCESS,
        s_verify_negotiation));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_negotiation_basic_auth_negotiate_success, s_socks5_negotiation_basic_auth_negotiate_success_fn)

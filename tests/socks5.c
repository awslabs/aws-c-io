/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/l4_proxy.h>

#include <aws/io/private/socks5_impl.h>
#include <aws/io/socks5.h>
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
    struct aws_l4_proxy_negotiation_context *negotiation_step_context;
    size_t chunk_length;
    int expected_final_error_code;
};

static int s_verify_negotiation(void *verify_context) {
    struct auth_negotiation_test_context *context = verify_context;

    ASSERT_INT_EQUALS(0, context->output_buffer->len);                  // nothing was written
    ASSERT_INT_EQUALS(0, context->negotiation_step_context->data->len); // used all data

    if (context->input_cursor->len > 0) {
        ASSERT_INT_EQUALS(AWS_L4PPS_IN_PROGRESS, context->negotiation_step_context->status);
        ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, context->negotiation_step_context->error_code);
    } else {
        if (context->expected_final_error_code == AWS_ERROR_SUCCESS) {
            ASSERT_INT_EQUALS(AWS_L4PPS_SUCCESS, context->negotiation_step_context->status);
        } else {
            ASSERT_INT_EQUALS(AWS_L4PPS_FAILURE, context->negotiation_step_context->status);
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
            struct aws_l4_proxy_negotiation_context context;
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
        .username = aws_byte_cursor_from_c_str("sponge"),
        .password = aws_byte_cursor_from_c_str("bob"),
    };

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
    struct aws_l4_proxy_negotiation_context *negotiation_step_context;
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

                struct aws_l4_proxy_negotiation_context context;
                AWS_ZERO_STRUCT(context);

                while (chunk_cursor.len > 0) {
                    context.data = &chunk_cursor;
                    context.to_write = &output_buffer;

                    aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(instance, &context);

                    ASSERT_INT_EQUALS(AWS_L4PPS_IN_PROGRESS, context.status);

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
                    ASSERT_INT_EQUALS(AWS_L4PPS_IN_PROGRESS, context.status);
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

static int s_socks5_impl_no_auth_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_options options = {
        .proxy_host = aws_byte_cursor_from_c_str("derp.com"),
        .proxy_port = 0,
        .negotiation_strategy = NULL,
        .negotiation_timeout_ms = 10000,
    };

    struct aws_l4_proxy_config *config = aws_l4_proxy_config_new_socks5(allocator, &options);
    struct aws_socks5_proxy_impl *impl = aws_socks5_proxy_impl_new(allocator, config->impl);

    aws_socks5_proxy_impl_destroy(impl);
    aws_l4_proxy_config_release(config);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_no_auth_create_destroy, s_socks5_impl_no_auth_create_destroy_fn)

static int s_socks5_impl_basic_auth_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_basic_auth_options basic_options = {
        .username = aws_byte_cursor_from_c_str("hello"),
        .password = aws_byte_cursor_from_c_str("there"),
    };

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        aws_socks5_proxy_negotiation_strategy_new_basic_auth(allocator, &basic_options);

    struct aws_socks5_proxy_options options = {
        .proxy_host = aws_byte_cursor_from_c_str("derp.com"),
        .proxy_port = 0,
        .negotiation_strategy = strategy,
        .negotiation_timeout_ms = 10000,
    };

    struct aws_l4_proxy_config *config = aws_l4_proxy_config_new_socks5(allocator, &options);
    struct aws_socks5_proxy_impl *impl = aws_socks5_proxy_impl_new(allocator, config->impl);

    aws_socks5_proxy_impl_destroy(impl);
    aws_l4_proxy_config_release(config);
    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_basic_auth_create_destroy, s_socks5_impl_basic_auth_create_destroy_fn)

struct socks5_protocol_testing_step {
    struct aws_byte_cursor input_data;
    struct aws_byte_cursor expected_output;
    int expected_error_code;
    enum aws_l4_proxy_protocol_status expected_final_status;
};

struct socks5_protocol_testing_step_options {
    struct aws_allocator *allocator;
    size_t input_chunk_size;
    size_t output_chunk_size;
};

static int s_apply_protocol_testing_step(
    struct aws_socks5_proxy_impl *impl,
    struct socks5_protocol_testing_step *step,
    struct socks5_protocol_testing_step_options *options) {
    struct aws_allocator *allocator = options->allocator;

    struct aws_byte_cursor input_cursor = step->input_data;

    struct aws_byte_buf temp_output;
    aws_byte_buf_init(&temp_output, allocator, options->output_chunk_size);

    struct aws_byte_buf full_output;
    aws_byte_buf_init(&full_output, allocator, 1024);

    int last_error_code = AWS_ERROR_SUCCESS;
    enum aws_l4_proxy_protocol_status last_status = AWS_L4PPS_IN_PROGRESS;

    // make sure we call it at least once
    bool driven = false;

    while ((input_cursor.len > 0 || !driven) && last_status == AWS_L4PPS_IN_PROGRESS) {
        struct aws_byte_cursor chunk_cursor =
            s_aws_byte_cursor_advance_clipped(&input_cursor, options->input_chunk_size);

        struct aws_l4_proxy_negotiation_context context;
        AWS_ZERO_STRUCT(context);

        context.data = &chunk_cursor;
        context.to_write = &temp_output;

        while (chunk_cursor.len > 0 || !driven) {
            aws_socks5_proxy_impl_drive_negotiation(impl, &context);
            last_error_code = context.error_code;
            last_status = context.status;

            struct aws_byte_cursor output_cursor = aws_byte_cursor_from_buf(&temp_output);
            if (output_cursor.len > 0) {
                aws_byte_buf_append_dynamic(&full_output, &output_cursor);
            }

            aws_byte_buf_reset(&temp_output, false);
            driven = true;
        }
    }

    while ((full_output.len < step->expected_output.len) && last_status == AWS_L4PPS_IN_PROGRESS) {
        struct aws_l4_proxy_negotiation_context context;
        AWS_ZERO_STRUCT(context);

        context.to_write = &temp_output;

        aws_socks5_proxy_impl_drive_negotiation(impl, &context);
        last_error_code = context.error_code;
        last_status = context.status;

        struct aws_byte_cursor output_cursor = aws_byte_cursor_from_buf(&temp_output);
        if (output_cursor.len > 0) {
            aws_byte_buf_append_dynamic(&full_output, &output_cursor);
        }

        aws_byte_buf_reset(&temp_output, false);
    }

    ASSERT_INT_EQUALS(step->expected_error_code, last_error_code);
    ASSERT_INT_EQUALS(step->expected_final_status, last_status);
    ASSERT_BIN_ARRAYS_EQUALS(step->expected_output.ptr, step->expected_output.len, full_output.buffer, full_output.len);

    aws_byte_buf_clean_up(&temp_output);
    aws_byte_buf_clean_up(&full_output);

    return AWS_OP_SUCCESS;
}

static int s_run_testing_steps(
    struct aws_socks5_proxy_impl *impl,
    struct socks5_protocol_testing_step **steps,
    size_t num_steps,
    struct socks5_protocol_testing_step_options *options) {
    for (size_t i = 0; i < num_steps; ++i) {
        ASSERT_SUCCESS(s_apply_protocol_testing_step(impl, steps[i], options));
    }

    return AWS_OP_SUCCESS;
}

static size_t test_matrix_chunk_sizes[] = {1, 2, 3, 5, 7, 11, 19, 31};

static int s_run_test_matrix(
    struct aws_socks5_proxy_negotiation_strategy *strategy,
    struct aws_allocator *allocator,
    struct socks5_protocol_testing_step **steps,
    size_t num_steps) {
    for (size_t i = 0; i < AWS_ARRAY_SIZE(test_matrix_chunk_sizes); ++i) {
        for (size_t j = 0; j < AWS_ARRAY_SIZE(test_matrix_chunk_sizes); ++j) {
            struct aws_socks5_proxy_options proxy_options = {
                .proxy_host = aws_byte_cursor_from_c_str("krusty.krab.com"),
                .proxy_port = 80,
                .negotiation_strategy = strategy,
                .negotiation_timeout_ms = 1000,
            };

            struct aws_l4_proxy_config *config = aws_l4_proxy_config_new_socks5(allocator, &proxy_options);

            struct aws_socks5_proxy_impl *impl = aws_socks5_proxy_impl_new(allocator, config->impl);

            struct socks5_protocol_testing_step_options test_options = {
                .allocator = allocator,
                .input_chunk_size = test_matrix_chunk_sizes[j],
                .output_chunk_size = test_matrix_chunk_sizes[i]};

            ASSERT_SUCCESS(s_run_testing_steps(impl, steps, num_steps, &test_options));

            aws_socks5_proxy_impl_destroy(impl);
            aws_l4_proxy_config_release(config);
        }
    }

    return AWS_OP_SUCCESS;
}

static uint8_t no_auth_expected_methods_bytes[] = {0x05, 0x01, 0x00};
static struct socks5_protocol_testing_step no_auth_methods_step = {
    .input_data = {.ptr = NULL, .len = 0},
    .expected_output = {.ptr = no_auth_expected_methods_bytes, .len = AWS_ARRAY_SIZE(no_auth_expected_methods_bytes)},
    .expected_error_code = AWS_ERROR_SUCCESS,
    .expected_final_status = AWS_L4PPS_IN_PROGRESS,
};

static uint8_t connect_request_bytes[] = {
    0x05, 0x01, 0x00, 0x03, 0x0F, 0x6B, 0x72, 0x75, 0x73, 0x74,
    0x79, 0x2E, 0x6B, 0x72, 0x61, 0x62, 0x2E, 0x63, 0x6F, 0x6D, // "krusty.krab.com"
    0x00, 0x50                                                  // port 80
};
static uint8_t no_auth_method_selection_bytes[] = {0x05, 0x00};
static struct socks5_protocol_testing_step no_auth_method_selection_step = {
    .input_data = {.ptr = no_auth_method_selection_bytes, .len = AWS_ARRAY_SIZE(no_auth_method_selection_bytes)},
    .expected_output = {.ptr = connect_request_bytes, .len = AWS_ARRAY_SIZE(connect_request_bytes)},
    .expected_error_code = AWS_ERROR_SUCCESS,
    .expected_final_status = AWS_L4PPS_IN_PROGRESS,
};

static uint8_t connect_response_success_bytes[] = {
    0x05,
    0x00,
    0x00,
    0x01,
    0x7F,
    0x00,
    0x00,
    0x01,
    0x00,
    0x51 // 127.0.0.1:81 outbound addr
};
static struct socks5_protocol_testing_step connect_response_success_step = {
    .input_data = {.ptr = connect_response_success_bytes, .len = AWS_ARRAY_SIZE(connect_response_success_bytes)},
    .expected_output = {.ptr = NULL, .len = 0},
    .expected_error_code = AWS_ERROR_SUCCESS,
    .expected_final_status = AWS_L4PPS_SUCCESS,
};

static int s_socks5_impl_no_auth_negotiation_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct socks5_protocol_testing_step *steps[] = {
        &no_auth_methods_step,
        &no_auth_method_selection_step,
        &connect_response_success_step,
    };

    s_run_test_matrix(NULL, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_no_auth_negotiation_success, s_socks5_impl_no_auth_negotiation_success_fn)

static uint8_t basic_auth_expected_methods_bytes[] = {0x05, 0x01, 0x02};
static struct socks5_protocol_testing_step basic_auth_methods_step = {
    .input_data = {.ptr = NULL, .len = 0},
    .expected_output =
        {.ptr = basic_auth_expected_methods_bytes, .len = AWS_ARRAY_SIZE(basic_auth_expected_methods_bytes)},
    .expected_error_code = AWS_ERROR_SUCCESS,
    .expected_final_status = AWS_L4PPS_IN_PROGRESS,
};

static uint8_t basic_auth_request_bytes[] = {0x01, 0x06, 0x73, 0x70, 0x6F, 0x6E, 0x67, 0x65, 0x03, 0x62, 0x6F, 0x62};
static uint8_t basic_auth_method_selection_bytes[] = {0x05, 0x02};
static struct socks5_protocol_testing_step basic_auth_method_selection_step = {
    .input_data = {.ptr = basic_auth_method_selection_bytes, .len = AWS_ARRAY_SIZE(basic_auth_method_selection_bytes)},
    .expected_output = {.ptr = basic_auth_request_bytes, .len = AWS_ARRAY_SIZE(basic_auth_request_bytes)},
    .expected_error_code = AWS_ERROR_SUCCESS,
    .expected_final_status = AWS_L4PPS_IN_PROGRESS,
};

static uint8_t basic_auth_success_bytes[] = {0x01, 0x00};
static struct socks5_protocol_testing_step basic_auth_response_step = {
    .input_data = {.ptr = basic_auth_success_bytes, .len = AWS_ARRAY_SIZE(basic_auth_success_bytes)},
    .expected_output = {.ptr = connect_request_bytes, .len = AWS_ARRAY_SIZE(connect_request_bytes)},
    .expected_error_code = AWS_ERROR_SUCCESS,
    .expected_final_status = AWS_L4PPS_IN_PROGRESS,
};

static int s_socks5_impl_basic_auth_negotiation_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    struct socks5_protocol_testing_step *steps[] = {
        &basic_auth_methods_step,
        &basic_auth_method_selection_step,
        &basic_auth_response_step,
        &connect_response_success_step,
    };

    s_run_test_matrix(strategy, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_basic_auth_negotiation_success, s_socks5_impl_basic_auth_negotiation_success_fn)

struct aws_socks5_proxy_negotiation_strategy_bad_methods {
    struct aws_socks5_proxy_negotiation_strategy base;

    int (*get_methods)(struct aws_socks5_proxy_negotiation_strategy_instance *, struct aws_array_list *);
};

static void s_aws_socks5_proxy_negotiation_strategy_bad_methods_final_release(void *value) {
    if (value == NULL) {
        return;
    }

    struct aws_socks5_proxy_negotiation_strategy *base = value;
    struct aws_socks5_proxy_negotiation_strategy_bad_methods *strategy = base->impl;

    aws_mem_release(strategy->base.allocator, strategy);
}

struct aws_socks5_proxy_negotiation_strategy_instance_bad_methods {
    struct aws_socks5_proxy_negotiation_strategy_instance base;

    int (*get_methods)(struct aws_socks5_proxy_negotiation_strategy_instance *, struct aws_array_list *);
};

static void s_aws_socks5_proxy_negotiation_strategy_instance_bad_methods_destroy(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance) {
    if (instance == NULL) {
        return;
    }

    struct aws_socks5_proxy_negotiation_strategy_instance_bad_methods *bad_methods_instance = instance->impl;

    aws_mem_release(bad_methods_instance->base.allocator, bad_methods_instance);
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_bad_methods_drive_negotiation(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_l4_proxy_negotiation_context *context) {

    context->status = AWS_L4PPS_FAILURE;
    context->error_code = AWS_ERROR_UNIMPLEMENTED;
}

static int s_aws_socks5_proxy_negotiation_strategy_instance_bad_methods_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    (void)instance;

    struct aws_socks5_proxy_negotiation_strategy_instance_bad_methods *bad_methods_instance = instance->impl;
    return (*bad_methods_instance).get_methods(instance, methods);
}

static struct aws_socks5_proxy_negotiation_strategy_instance_vtable s_bad_methods_strategy_instance_vtable = {
    .destroy = s_aws_socks5_proxy_negotiation_strategy_instance_bad_methods_destroy,
    .drive_negotiation = s_aws_socks5_proxy_negotiation_strategy_instance_bad_methods_drive_negotiation,
    .get_auth_methods = s_aws_socks5_proxy_negotiation_strategy_instance_bad_methods_get_auth_methods,
};

static struct aws_socks5_proxy_negotiation_strategy_instance *
    s_aws_socks5_proxy_negotiation_strategy_bad_methods_new_instance(
        struct aws_socks5_proxy_negotiation_strategy *strategy) {
    struct aws_socks5_proxy_negotiation_strategy_instance_bad_methods *instance = aws_mem_calloc(
        strategy->allocator, 1, sizeof(struct aws_socks5_proxy_negotiation_strategy_instance_bad_methods));
    instance->base.allocator = strategy->allocator;
    instance->base.vtable = &s_bad_methods_strategy_instance_vtable;
    instance->base.impl = instance;

    struct aws_socks5_proxy_negotiation_strategy_bad_methods *bad_methods_strategy = strategy->impl;
    instance->get_methods = bad_methods_strategy->get_methods;

    return &instance->base;
}

static struct aws_socks5_proxy_negotiation_strategy_vtable s_bad_methods_strategy_vtable = {
    .new_instance = s_aws_socks5_proxy_negotiation_strategy_bad_methods_new_instance,
};

static struct aws_socks5_proxy_negotiation_strategy *s_aws_socks5_proxy_negotiation_strategy_new_bad_methods(
    struct aws_allocator *allocator,
    int (*get_methods)(struct aws_socks5_proxy_negotiation_strategy_instance *, struct aws_array_list *)) {
    struct aws_socks5_proxy_negotiation_strategy_bad_methods *strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_negotiation_strategy_bad_methods));

    strategy->base.allocator = allocator;
    strategy->base.vtable = &s_bad_methods_strategy_vtable;
    strategy->base.impl = strategy;
    aws_ref_count_init(
        &strategy->base.ref_count, &strategy->base, s_aws_socks5_proxy_negotiation_strategy_bad_methods_final_release);
    strategy->get_methods = get_methods;

    return &strategy->base;
}

static struct socks5_protocol_testing_step bad_methods_step = {
    .input_data = {.ptr = NULL, .len = 0},
    .expected_output = {.ptr = NULL, .len = 0},
    .expected_error_code = AWS_IO_SOCKS5_INTERNAL_FAILURE,
    .expected_final_status = AWS_L4PPS_FAILURE,
};

static int s_get_methods_none(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    (void)instance;
    (void)methods;

    return AWS_OP_SUCCESS;
}

static int s_socks5_impl_no_methods_failure_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        s_aws_socks5_proxy_negotiation_strategy_new_bad_methods(allocator, s_get_methods_none);

    struct socks5_protocol_testing_step *steps[] = {
        &bad_methods_step,
    };

    s_run_test_matrix(strategy, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_no_methods_failure, s_socks5_impl_no_methods_failure_fn)

static int s_get_methods_too_many(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    (void)instance;

    for (size_t i = 0; i < 256; ++i) {
        uint8_t method = i % 256;
        aws_array_list_push_back(methods, &method);
    }

    return AWS_OP_SUCCESS;
}

static int s_socks5_impl_too_many_methods_failure_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy =
        s_aws_socks5_proxy_negotiation_strategy_new_bad_methods(allocator, s_get_methods_too_many);

    struct socks5_protocol_testing_step *steps[] = {
        &bad_methods_step,
    };

    s_run_test_matrix(strategy, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_too_many_methods_failure, s_socks5_impl_too_many_methods_failure_fn)

static uint8_t basic_auth_response_rejected_bytes[] = {0x01, 0x01};
static struct socks5_protocol_testing_step basic_auth_response_rejected_step = {
    .input_data =
        {.ptr = basic_auth_response_rejected_bytes, .len = AWS_ARRAY_SIZE(basic_auth_response_rejected_bytes)},
    .expected_output = {.ptr = NULL, .len = 0},
    .expected_error_code = AWS_IO_SOCKS5_SUBNEGOTIATION_REJECTED,
    .expected_final_status = AWS_L4PPS_FAILURE,
};

static int s_socks5_impl_auth_subnegotiation_failure_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    struct socks5_protocol_testing_step *steps[] = {
        &basic_auth_methods_step,
        &basic_auth_method_selection_step,
        &basic_auth_response_rejected_step,
    };

    s_run_test_matrix(strategy, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_auth_subnegotiation_failure, s_socks5_impl_auth_subnegotiation_failure_fn)

static uint8_t connect_response_bad_address_type_bytes[] = {
    0x05,
    0x00,
    0x00,
    0x07, // bad address type
    0x7F,
    0x00,
    0x00,
    0x01,
    0x00,
    0x51 // 127.0.0.1:81 outbound addr
};
static struct socks5_protocol_testing_step connect_response_bad_address_type_step = {
    .input_data =
        {.ptr = connect_response_bad_address_type_bytes,
         .len = AWS_ARRAY_SIZE(connect_response_bad_address_type_bytes)},
    .expected_output = {.ptr = NULL, .len = 0},
    .expected_error_code = AWS_IO_SOCKS5_PROTOCOL_FAILURE,
    .expected_final_status = AWS_L4PPS_FAILURE,
};

static int s_socks5_impl_connect_response_bad_address_type_failure_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    struct socks5_protocol_testing_step *steps[] = {
        &basic_auth_methods_step,
        &basic_auth_method_selection_step,
        &basic_auth_response_step,
        &connect_response_bad_address_type_step,
    };

    s_run_test_matrix(strategy, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    socks5_impl_connect_response_bad_address_type_failure,
    s_socks5_impl_connect_response_bad_address_type_failure_fn)

static uint8_t connect_refused_bytes[] = {
    0x05,
    0x01, // connect refused
    0x00,
    0x01,
    0x7F,
    0x00,
    0x00,
    0x01,
    0x00,
    0x51 // 127.0.0.1:81 outbound addr
};
static struct socks5_protocol_testing_step connect_refused_step = {
    .input_data = {.ptr = connect_refused_bytes, .len = AWS_ARRAY_SIZE(connect_refused_bytes)},
    .expected_output = {.ptr = NULL, .len = 0},
    .expected_error_code = AWS_IO_SOCKS5_CONNECT_REQUEST_FAILED,
    .expected_final_status = AWS_L4PPS_FAILURE,
};

static int s_socks5_impl_connect_refused_failure_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *strategy = s_create_basic_auth_strategy(allocator);

    struct socks5_protocol_testing_step *steps[] = {
        &basic_auth_methods_step,
        &basic_auth_method_selection_step,
        &basic_auth_response_step,
        &connect_refused_step,
    };

    s_run_test_matrix(strategy, allocator, steps, AWS_ARRAY_SIZE(steps));

    aws_socks5_proxy_negotiation_strategy_release(strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socks5_impl_connect_refused_failure, s_socks5_impl_connect_refused_failure_fn)
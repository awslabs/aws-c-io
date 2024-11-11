/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/retry_strategy.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>

#include <aws/io/event_loop.h>

struct exponential_backoff_test_data {
    size_t retry_count;
    size_t client_error_count;
    int failure_error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable cvar;
};

static void s_too_many_retries_test_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)error_code;

    struct exponential_backoff_test_data *test_data = user_data;
    enum aws_retry_error_type error_type = AWS_RETRY_ERROR_TYPE_SERVER_ERROR;

    aws_mutex_lock(&test_data->mutex);
    test_data->retry_count += 1;

    if (test_data->client_error_count) {
        error_type = AWS_RETRY_ERROR_TYPE_CLIENT_ERROR;
        test_data->client_error_count--;
    }
    aws_mutex_unlock(&test_data->mutex);

    if (aws_retry_strategy_schedule_retry(token, error_type, s_too_many_retries_test_on_retry_ready, user_data)) {
        aws_mutex_lock(&test_data->mutex);
        test_data->failure_error_code = aws_last_error();
        aws_mutex_unlock(&test_data->mutex);
        aws_retry_token_release(token);
        aws_condition_variable_notify_all(&test_data->cvar);
    }
}

static void s_too_many_retries_test_token_acquired(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)retry_strategy;
    (void)error_code;

    aws_retry_strategy_schedule_retry(
        token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_too_many_retries_test_on_retry_ready, user_data);
}

static bool s_retry_has_failed(void *arg) {
    struct exponential_backoff_test_data *test_data = arg;
    return test_data->failure_error_code != AWS_OP_SUCCESS;
}

static int s_test_exponential_backoff_retry_too_many_retries_for_jitter_mode(
    struct aws_allocator *allocator,
    enum aws_exponential_backoff_jitter_mode jitter_mode) {

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_exponential_backoff_retry_options config = {
        .max_retries = 3,
        .jitter_mode = jitter_mode,
        .el_group = el_group,
    };

    struct aws_retry_strategy *retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &config);
    ASSERT_NOT_NULL(retry_strategy);

    struct exponential_backoff_test_data test_data = {
        .retry_count = 0,
        .failure_error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_data.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        retry_strategy, NULL, s_too_many_retries_test_token_acquired, &test_data, 0));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&test_data.cvar, &test_data.mutex, s_retry_has_failed, &test_data));
    aws_mutex_unlock(&test_data.mutex);

    ASSERT_UINT_EQUALS(config.max_retries, test_data.retry_count);
    ASSERT_UINT_EQUALS(AWS_IO_MAX_RETRIES_EXCEEDED, test_data.failure_error_code);

    aws_retry_strategy_release(retry_strategy);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

/* Test that no jitter mode exponential back-off fails after max retries are exceeded. */
static int s_test_exponential_backoff_retry_too_many_retries_no_jitter_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_exponential_backoff_retry_too_many_retries_for_jitter_mode(
        allocator, AWS_EXPONENTIAL_BACKOFF_JITTER_NONE);
}

AWS_TEST_CASE(
    test_exponential_backoff_retry_too_many_retries_no_jitter,
    s_test_exponential_backoff_retry_too_many_retries_no_jitter_fn)

/* Test that full jitter mode exponential back-off fails after max retries are exceeded. */
static int s_test_exponential_backoff_retry_too_many_retries_full_jitter_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    return s_test_exponential_backoff_retry_too_many_retries_for_jitter_mode(
        allocator, AWS_EXPONENTIAL_BACKOFF_JITTER_FULL);
}

AWS_TEST_CASE(
    test_exponential_backoff_retry_too_many_retries_full_jitter,
    s_test_exponential_backoff_retry_too_many_retries_full_jitter_fn)

/* Test that decorrelated jitter mode exponential back-off fails after max retries are exceeded. */
static int s_test_exponential_backoff_retry_too_many_retries_decorrelated_jitter_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    return s_test_exponential_backoff_retry_too_many_retries_for_jitter_mode(
        allocator, AWS_EXPONENTIAL_BACKOFF_JITTER_DECORRELATED);
}

AWS_TEST_CASE(
    test_exponential_backoff_retry_too_many_retries_decorrelated_jitter,
    s_test_exponential_backoff_retry_too_many_retries_decorrelated_jitter_fn)

/* Test that default jitter mode exponential back-off fails after max retries are exceeded. */
static int s_test_exponential_backoff_retry_too_many_retries_default_jitter_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;
    return s_test_exponential_backoff_retry_too_many_retries_for_jitter_mode(
        allocator, AWS_EXPONENTIAL_BACKOFF_JITTER_DEFAULT);
}

AWS_TEST_CASE(
    test_exponential_backoff_retry_too_many_retries_default_jitter,
    s_test_exponential_backoff_retry_too_many_retries_default_jitter_fn)

/* Test that client failures do not count against the max retry budget. */
static int s_test_exponential_backoff_retry_client_errors_do_not_count_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_exponential_backoff_retry_options config = {
        .el_group = el_group,
        .max_retries = 3,
    };

    struct aws_retry_strategy *retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &config);
    ASSERT_NOT_NULL(retry_strategy);

    struct exponential_backoff_test_data test_data = {
        .retry_count = 0,
        .failure_error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
        .client_error_count = 2,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_data.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        retry_strategy, NULL, s_too_many_retries_test_token_acquired, &test_data, 0));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&test_data.cvar, &test_data.mutex, s_retry_has_failed, &test_data));
    aws_mutex_unlock(&test_data.mutex);

    ASSERT_UINT_EQUALS(config.max_retries + 2, test_data.retry_count);
    ASSERT_UINT_EQUALS(AWS_IO_MAX_RETRIES_EXCEEDED, test_data.failure_error_code);

    aws_retry_strategy_release(retry_strategy);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_exponential_backoff_retry_client_errors_do_not_count,
    s_test_exponential_backoff_retry_client_errors_do_not_count_fn)

/* Test that in no jitter mode, exponential backoff is actually applied as documented. */
static int s_test_exponential_backoff_retry_no_jitter_time_taken_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_exponential_backoff_retry_options config = {
        .max_retries = 3,
        .jitter_mode = AWS_EXPONENTIAL_BACKOFF_JITTER_NONE,
        .el_group = el_group,
    };

    struct aws_retry_strategy *retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &config);
    ASSERT_NOT_NULL(retry_strategy);

    struct exponential_backoff_test_data test_data = {
        .retry_count = 0,
        .failure_error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    uint64_t before_time = 0;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&before_time));
    ASSERT_SUCCESS(aws_mutex_lock(&test_data.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        retry_strategy, NULL, s_too_many_retries_test_token_acquired, &test_data, 0));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&test_data.cvar, &test_data.mutex, s_retry_has_failed, &test_data));
    aws_mutex_unlock(&test_data.mutex);
    uint64_t after_time = 0;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&after_time));
    uint64_t backoff_scale_factor =
        aws_timestamp_convert(config.backoff_scale_factor_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t expected_interval = (1 * backoff_scale_factor) + (2 * backoff_scale_factor) + (4 * backoff_scale_factor);
    ASSERT_TRUE(expected_interval <= after_time - before_time);

    ASSERT_UINT_EQUALS(config.max_retries, test_data.retry_count);
    ASSERT_UINT_EQUALS(AWS_IO_MAX_RETRIES_EXCEEDED, test_data.failure_error_code);

    aws_retry_strategy_release(retry_strategy);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    test_exponential_backoff_retry_no_jitter_time_taken,
    s_test_exponential_backoff_retry_no_jitter_time_taken_fn)

/* Test that in no jitter mode, max exponential backoff is actually applied as documented. */
static int s_test_exponential_max_backoff_retry_no_jitter_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_exponential_backoff_retry_options config = {
        .max_retries = 3,
        .jitter_mode = AWS_EXPONENTIAL_BACKOFF_JITTER_NONE,
        .el_group = el_group,
        .backoff_scale_factor_ms = 1000,
        .max_backoff_secs = 3,
    };

    struct aws_retry_strategy *retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &config);
    ASSERT_NOT_NULL(retry_strategy);

    struct exponential_backoff_test_data test_data = {
        .retry_count = 0,
        .failure_error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    uint64_t before_time = 0;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&before_time));
    ASSERT_SUCCESS(aws_mutex_lock(&test_data.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        retry_strategy, NULL, s_too_many_retries_test_token_acquired, &test_data, 0));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&test_data.cvar, &test_data.mutex, s_retry_has_failed, &test_data));
    aws_mutex_unlock(&test_data.mutex);
    uint64_t after_time = 0;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&after_time));
    uint64_t backoff_scale_factor =
        aws_timestamp_convert(config.backoff_scale_factor_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t max_backoff_scale_factor =
        aws_timestamp_convert(config.max_backoff_secs, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    uint64_t expected_interval = aws_min_u64(max_backoff_scale_factor, 1 * backoff_scale_factor) +
                                 aws_min_u64(max_backoff_scale_factor, 2 * backoff_scale_factor) +
                                 aws_min_u64(max_backoff_scale_factor, 4 * backoff_scale_factor);
    ASSERT_TRUE(expected_interval <= after_time - before_time);

    ASSERT_UINT_EQUALS(config.max_retries, test_data.retry_count);
    ASSERT_UINT_EQUALS(AWS_IO_MAX_RETRIES_EXCEEDED, test_data.failure_error_code);

    aws_retry_strategy_release(retry_strategy);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_exponential_max_backoff_retry_no_jitter, s_test_exponential_max_backoff_retry_no_jitter_fn)

/* verify that invalid options cause a failure at creation time. */
static int s_test_exponential_backoff_retry_invalid_options_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_exponential_backoff_retry_options config = {
        .max_retries = 64,
        .el_group = el_group,
    };

    struct aws_retry_strategy *retry_strategy = aws_retry_strategy_new_exponential_backoff(allocator, &config);
    ASSERT_NULL(retry_strategy);
    ASSERT_UINT_EQUALS(AWS_ERROR_INVALID_ARGUMENT, aws_last_error());

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_exponential_backoff_retry_invalid_options, s_test_exponential_backoff_retry_invalid_options_fn)

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/retry_strategy.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/shutdown_types.h>

#include <aws/io/event_loop.h>

/* Fixture: an el_group plus an adaptive strategy, mirroring the standard retry test fixture. */
struct adaptive_test_data {
    struct aws_event_loop_group *el_group;
    struct aws_retry_strategy *retry_strategy;
    bool fast_fail_if_no_token;
    size_t initial_bucket_capacity;
    struct aws_mutex mutex;
    struct aws_condition_variable cvar;
    bool el_group_shutdown;
};

/* Default fixture: pacing mode (fast_fail off), standard quota bucket of 15. */
static struct adaptive_test_data s_fixture_test_data = {
    .cvar = AWS_CONDITION_VARIABLE_INIT,
    .mutex = AWS_MUTEX_INIT,
    .initial_bucket_capacity = 15,
};

/* Fast-fail fixture: the gate denies instead of deferring when no token is available. */
static struct adaptive_test_data s_fast_fail_fixture_test_data = {
    .cvar = AWS_CONDITION_VARIABLE_INIT,
    .mutex = AWS_MUTEX_INIT,
    .fast_fail_if_no_token = true,
    .initial_bucket_capacity = 15,
};

static void s_adaptive_el_group_completion_callback(void *arg) {
    struct adaptive_test_data *test_data = arg;
    aws_mutex_lock(&test_data->mutex);
    test_data->el_group_shutdown = true;
    aws_mutex_unlock(&test_data->mutex);
    aws_condition_variable_notify_one(&test_data->cvar);
}

static bool s_adaptive_el_group_shutdown_predicate(void *arg) {
    struct adaptive_test_data *test_data = arg;
    return test_data->el_group_shutdown;
}

static int s_adaptive_fixture_setup(struct aws_allocator *allocator, void *ctx) {
    aws_io_library_init(allocator);
    struct adaptive_test_data *test_data = ctx;
    struct aws_shutdown_callback_options shutdown_options = {
        .shutdown_callback_fn = s_adaptive_el_group_completion_callback,
        .shutdown_callback_user_data = ctx,
    };

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
        .shutdown_options = &shutdown_options,
    };
    test_data->el_group = aws_event_loop_group_new(allocator, &elg_options);
    ASSERT_NOT_NULL(test_data->el_group);

    struct aws_adaptive_retry_options retry_options = {
        .standard_options =
            {
                .initial_bucket_capacity = test_data->initial_bucket_capacity,
                .backoff_retry_options =
                    {
                        .el_group = test_data->el_group,
                    },
            },
        .fast_fail_if_no_token = test_data->fast_fail_if_no_token,
    };
    test_data->retry_strategy = aws_retry_strategy_new_adaptive(allocator, &retry_options);
    ASSERT_NOT_NULL(test_data->retry_strategy);

    return AWS_OP_SUCCESS;
}

static int s_adaptive_fixture_shutdown(struct aws_allocator *allocator, int setup_error_code, void *ctx) {
    (void)allocator;

    if (!setup_error_code) {
        struct adaptive_test_data *test_data = ctx;
        aws_mutex_lock(&test_data->mutex);
        aws_retry_strategy_release(test_data->retry_strategy);
        aws_event_loop_group_release(test_data->el_group);
        aws_condition_variable_wait_pred(
            &test_data->cvar, &test_data->mutex, s_adaptive_el_group_shutdown_predicate, ctx);
        aws_mutex_unlock(&test_data->mutex);
    }

    aws_io_library_clean_up();
    return AWS_OP_SUCCESS;
}

/* Per-operation async state, same shape the standard test uses. */
struct adaptive_retry_data {
    struct aws_retry_token *retry_token;
    struct aws_retry_strategy *retry_strategy;
    struct aws_mutex mutex;
    struct aws_condition_variable cvar;
    int token_acquisition_error_code;
    bool token_acquisition_fired;
    int schedule_retry_error_code;
    struct aws_retry_token *schedule_token_value;
    bool retry_ready_fired;
};

static bool s_adaptive_token_acquisition_completed(void *arg) {
    struct adaptive_retry_data *retry_data = arg;
    return retry_data->token_acquisition_fired;
}

static void s_on_adaptive_token_acquired_cb(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {

    struct adaptive_retry_data *retry_data = user_data;
    aws_mutex_lock(&retry_data->mutex);
    retry_data->retry_token = token;
    retry_data->token_acquisition_error_code = error_code;
    retry_data->retry_strategy = retry_strategy;
    retry_data->token_acquisition_fired = true;
    aws_mutex_unlock(&retry_data->mutex);
    aws_condition_variable_notify_one(&retry_data->cvar);
}

static bool s_adaptive_retry_ready_completed(void *arg) {
    struct adaptive_retry_data *retry_data = arg;
    return retry_data->retry_ready_fired;
}

static void s_on_adaptive_retry_ready_cb(struct aws_retry_token *token, int error_code, void *user_data) {
    struct adaptive_retry_data *retry_data = user_data;
    aws_mutex_lock(&retry_data->mutex);
    retry_data->schedule_retry_error_code = error_code;
    retry_data->schedule_token_value = token;
    retry_data->retry_ready_fired = true;
    aws_mutex_unlock(&retry_data->mutex);
    aws_condition_variable_notify_one(&retry_data->cvar);
}

/* Acquires a token through the gate and blocks until the acquired callback fires. */
static int s_acquire_token_blocking(
    struct adaptive_test_data *test_data,
    struct adaptive_retry_data *retry_data,
    const struct aws_byte_cursor *partition) {

    retry_data->retry_token = NULL;
    retry_data->token_acquisition_error_code = 0;
    retry_data->token_acquisition_fired = false;

    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        test_data->retry_strategy, partition, s_on_adaptive_token_acquired_cb, retry_data, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data->cvar, &retry_data->mutex, s_adaptive_token_acquisition_completed, retry_data));

    return AWS_OP_SUCCESS;
}

/* Schedules a retry through the gate and blocks until retry-ready fires. Clears the ready flags first. */
static int s_schedule_retry_blocking(struct adaptive_retry_data *retry_data, enum aws_retry_error_type error_type) {

    retry_data->schedule_retry_error_code = 0;
    retry_data->schedule_token_value = NULL;
    retry_data->retry_ready_fired = false;

    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data->retry_token, error_type, s_on_adaptive_retry_ready_cb, retry_data));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data->cvar, &retry_data->mutex, s_adaptive_retry_ready_completed, retry_data));

    return AWS_OP_SUCCESS;
}

/* Construct and destroy the strategy with no operations. */
static int s_test_adaptive_retry_strategy_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_setup_shutdown,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_setup_shutdown,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* The el_group is a required precondition; constructing without one returns NULL. */
static int s_test_adaptive_retry_strategy_requires_el_group(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_adaptive_retry_options bad_options = {
        .standard_options =
            {
                .initial_bucket_capacity = 10,
            },
    };
    struct aws_retry_strategy *strategy = aws_retry_strategy_new_adaptive(allocator, &bad_options);
    ASSERT_NULL(strategy);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_adaptive_retry_strategy_requires_el_group, s_test_adaptive_retry_strategy_requires_el_group)

/* Acquire a token, record success, release. While disabled the gate adds no pacing. */
static int s_test_adaptive_retry_strategy_acquire_and_success(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-east-1:adaptive-success");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));

    ASSERT_PTR_EQUALS(test_data->retry_strategy, retry_data.retry_strategy);
    ASSERT_NOT_NULL(retry_data.retry_token);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, retry_data.token_acquisition_error_code);

    ASSERT_SUCCESS(aws_retry_token_record_success(retry_data.retry_token));
    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_acquire_and_success,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_acquire_and_success,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* A throttling response enables the limiter and the retry still completes end to end through the gate. */
static int s_test_adaptive_retry_strategy_throttle_schedules_retry(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-east-1:adaptive-throttle");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_NOT_NULL(retry_data.retry_token);

    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_THROTTLING));
    ASSERT_PTR_EQUALS(retry_data.retry_token, retry_data.schedule_token_value);
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_throttle_schedules_retry,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_throttle_schedules_retry,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* Transient errors are neutral to the limiter. */
static int s_test_adaptive_retry_strategy_non_throttle_errors_neutral(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-west-2:adaptive-non-throttle");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_NOT_NULL(retry_data.retry_token);

    /* A transient error (bucket cost 10) retries; it never enables the rate limiter. */
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_TRANSIENT));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    /* A server error (bucket cost 5) retries; it grows the rate like a success. */
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_SERVER_ERROR));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_non_throttle_errors_retry,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_non_throttle_errors_retry,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* The adaptive strategy inherits standard's retry-quota: exhausting it denies further retries. */
static int s_test_adaptive_retry_strategy_inherits_quota_exhaustion(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-east-1:adaptive-quota");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_NOT_NULL(retry_data.retry_token);

    /* Capacity 15: a transient retry costs 10, a server retry costs 5, draining the bucket. */
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_TRANSIENT));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_SERVER_ERROR));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    /* Bucket now empty: the next retry is denied synchronously, inherited straight from standard. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_adaptive_retry_ready_cb, &retry_data));

    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_inherits_quota_exhaustion,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_inherits_quota_exhaustion,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* Recording success pays quota back, letting a previously-denied retry succeed, like standard. */
static int s_test_adaptive_retry_strategy_quota_recovers(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-west-2:adaptive-recover");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_NOT_NULL(retry_data.retry_token);

    /* Drain the bucket (10 + 5 == 15). */
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_TRANSIENT));
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_SERVER_ERROR));
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_adaptive_retry_ready_cb, &retry_data));
    aws_retry_token_release(retry_data.retry_token);

    /* Pay back 5 by recording success on 5 fresh tokens in the same partition. */
    for (int i = 0; i < 5; ++i) {
        ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
        ASSERT_SUCCESS(aws_retry_token_record_success(retry_data.retry_token));
        aws_retry_token_release(retry_data.retry_token);
    }

    /* A fresh token can now afford one server-error retry (cost 5). */
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_SERVER_ERROR));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    /* Only 5 was repaid, so the next retry is denied again. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_adaptive_retry_ready_cb, &retry_data));

    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_quota_recovers,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_quota_recovers,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* Two tokens on the same partition share one quota bucket, inherited from standard. */
static int s_test_adaptive_retry_strategy_shared_partition_bucket(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data first = {.mutex = AWS_MUTEX_INIT, .cvar = AWS_CONDITION_VARIABLE_INIT};
    struct adaptive_retry_data second = {.mutex = AWS_MUTEX_INIT, .cvar = AWS_CONDITION_VARIABLE_INIT};
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("eu-west-1:adaptive-shared");

    ASSERT_SUCCESS(aws_mutex_lock(&first.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &first, &partition));
    ASSERT_NOT_NULL(first.retry_token);
    aws_mutex_unlock(&first.mutex);

    ASSERT_SUCCESS(aws_mutex_lock(&second.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &second, &partition));
    ASSERT_NOT_NULL(second.retry_token);
    aws_mutex_unlock(&second.mutex);

    /* First token drains 10 (transient). */
    ASSERT_SUCCESS(aws_mutex_lock(&first.mutex));
    ASSERT_SUCCESS(s_schedule_retry_blocking(&first, AWS_RETRY_ERROR_TYPE_TRANSIENT));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, first.schedule_retry_error_code);
    aws_mutex_unlock(&first.mutex);

    /* Second token drains the remaining 5 (server). */
    ASSERT_SUCCESS(aws_mutex_lock(&second.mutex));
    ASSERT_SUCCESS(s_schedule_retry_blocking(&second, AWS_RETRY_ERROR_TYPE_SERVER_ERROR));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, second.schedule_retry_error_code);

    /* Bucket is shared and now empty: the second token is denied too. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            second.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_adaptive_retry_ready_cb, &second));
    aws_retry_token_release(second.retry_token);
    aws_mutex_unlock(&second.mutex);

    /* The first token sees the same exhausted bucket. */
    ASSERT_SUCCESS(aws_mutex_lock(&first.mutex));
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            first.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_adaptive_retry_ready_cb, &first));
    aws_retry_token_release(first.retry_token);
    aws_mutex_unlock(&first.mutex);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_shared_partition_bucket,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_shared_partition_bucket,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

/* A full acquire -> throttle -> retry-ready -> record_success cycle completes end to end. */
static int s_test_adaptive_retry_strategy_full_cycle(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-east-1:adaptive-full-cycle");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_NOT_NULL(retry_data.retry_token);

    /* Throttle once (enables the limiter and schedules a paced retry). */
    ASSERT_SUCCESS(s_schedule_retry_blocking(&retry_data, AWS_RETRY_ERROR_TYPE_THROTTLING));
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);

    /* The retry eventually succeeds: record success and release cleanly. */
    ASSERT_SUCCESS(aws_retry_token_record_success(retry_data.retry_token));
    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_full_cycle,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_full_cycle,
    s_adaptive_fixture_shutdown,
    &s_fixture_test_data);

static int s_test_adaptive_retry_strategy_fast_fail_config(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    struct adaptive_test_data *test_data = ctx;

    struct adaptive_retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };
    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-east-1:adaptive-fast-fail");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(s_acquire_token_blocking(test_data, &retry_data, &partition));
    ASSERT_NOT_NULL(retry_data.retry_token);

    /* schedule_retry on a throttle is accepted synchronously; it enables the limiter and schedules the retry. */
    retry_data.schedule_retry_error_code = 0;
    retry_data.schedule_token_value = NULL;
    retry_data.retry_ready_fired = false;
    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data.retry_token, AWS_RETRY_ERROR_TYPE_THROTTLING, s_on_adaptive_retry_ready_cb, &retry_data));

    /* Wait for the paced retry-ready. Its outcome is either success or the fast-fail denial; both are valid. */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_adaptive_retry_ready_completed, &retry_data));
    ASSERT_TRUE(
        retry_data.schedule_retry_error_code == AWS_ERROR_SUCCESS ||
        retry_data.schedule_retry_error_code == AWS_IO_RETRY_PERMISSION_DENIED);

    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_adaptive_retry_strategy_fast_fail_config,
    s_adaptive_fixture_setup,
    s_test_adaptive_retry_strategy_fast_fail_config,
    s_adaptive_fixture_shutdown,
    &s_fast_fail_fixture_test_data);

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
    struct aws_event_loop_group *el_group;
    struct aws_retry_strategy *retry_strategy;
    int failure_error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable cvar;
    bool el_group_shutdown;
};

static struct exponential_backoff_test_data s_fixture_test_data = {
    .cvar = AWS_CONDITION_VARIABLE_INIT,
    .mutex = AWS_MUTEX_INIT,
};

static void s_el_group_completion_callback(void *arg) {
    struct exponential_backoff_test_data *test_data = arg;

    aws_mutex_lock(&test_data->mutex);
    test_data->el_group_shutdown = true;
    aws_mutex_unlock(&test_data->mutex);
    aws_condition_variable_notify_one(&test_data->cvar);
}

static bool s_el_group_shutdown_predicate(void *arg) {
    struct exponential_backoff_test_data *test_data = arg;
    return test_data->el_group_shutdown;
}

static int s_fixture_setup(struct aws_allocator *allocator, void *ctx) {
    aws_io_library_init(allocator);
    struct exponential_backoff_test_data *test_data = ctx;
    struct aws_shutdown_callback_options shutdown_options = {
        .shutdown_callback_fn = s_el_group_completion_callback,
        .shutdown_callback_user_data = ctx,
    };

    test_data->el_group = aws_event_loop_group_new_default(allocator, 1, &shutdown_options);
    ASSERT_NOT_NULL(test_data->el_group);
    struct aws_standard_retry_options retry_options = {
        .initial_bucket_capacity = 15,
        .backoff_retry_options =
            {
                .el_group = test_data->el_group,
            },
    };
    test_data->retry_strategy = aws_retry_strategy_new_standard(allocator, &retry_options);
    ASSERT_NOT_NULL(test_data->retry_strategy);

    return AWS_OP_SUCCESS;
}

static int s_fixture_shutdown(struct aws_allocator *allocator, int setup_error_code, void *ctx) {
    (void)allocator;

    if (!setup_error_code) {
        struct exponential_backoff_test_data *test_data = ctx;

        aws_mutex_lock(&test_data->mutex);
        aws_retry_strategy_release(test_data->retry_strategy);
        aws_event_loop_group_release(test_data->el_group);
        aws_condition_variable_wait_pred(&test_data->cvar, &test_data->mutex, s_el_group_shutdown_predicate, ctx);
        aws_mutex_unlock(&test_data->mutex);
    }

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

static int s_test_standard_retry_strategy_setup_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE_FIXTURE(
    test_standard_retry_strategy_setup_shutdown,
    s_fixture_setup,
    s_test_standard_retry_strategy_setup_shutdown,
    s_fixture_shutdown,
    &s_fixture_test_data);

struct retry_data {
    struct aws_retry_token *retry_token;
    struct aws_retry_strategy *retry_strategy;
    struct aws_mutex mutex;
    struct aws_condition_variable cvar;
    int token_acquisition_error_code;
    int schedule_retry_error_code;
    struct aws_retry_token *schedule_token_value;
};

static bool s_retry_token_acquisition_completed(void *arg) {
    struct retry_data *retry_data = arg;
    return retry_data->retry_token || retry_data->token_acquisition_error_code;
}

static void s_on_retry_token_acquired(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {

    struct retry_data *retry_data = user_data;
    aws_mutex_lock(&retry_data->mutex);
    retry_data->retry_token = token;
    retry_data->token_acquisition_error_code = error_code;
    retry_data->retry_strategy = retry_strategy;
    aws_mutex_unlock(&retry_data->mutex);
    aws_condition_variable_notify_one(&retry_data->cvar);
}

static bool s_retry_ready_completion_predicate(void *arg) {
    struct retry_data *retry_data = arg;
    return retry_data->schedule_retry_error_code || retry_data->schedule_token_value;
}

static void s_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    struct retry_data *retry_data = user_data;
    aws_mutex_lock(&retry_data->mutex);
    retry_data->schedule_retry_error_code = error_code;
    retry_data->schedule_token_value = token;
    aws_mutex_unlock(&retry_data->mutex);
    aws_condition_variable_notify_one(&retry_data->cvar);
}

static int s_test_standard_retry_strategy_failure_exhausts_bucket(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;

    struct exponential_backoff_test_data *test_data = ctx;

    struct retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    struct retry_data retry_data_dup_same_partition = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_byte_cursor partition = aws_byte_cursor_from_c_str("us-east-1:super-badly-named-aws-service");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        test_data->retry_strategy, &partition, s_on_retry_token_acquired, &retry_data, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_token_acquisition_completed, &retry_data));

    ASSERT_PTR_EQUALS(test_data->retry_strategy, retry_data.retry_strategy);
    ASSERT_NOT_NULL(retry_data.retry_token);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, retry_data.token_acquisition_error_code);

    aws_mutex_unlock(&retry_data.mutex);
    /* do a duplicate partition, this should take a different path since the bucket already exists. */
    ASSERT_SUCCESS(aws_mutex_lock(&retry_data_dup_same_partition.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        test_data->retry_strategy, &partition, s_on_retry_token_acquired, &retry_data_dup_same_partition, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data_dup_same_partition.cvar,
        &retry_data_dup_same_partition.mutex,
        s_retry_token_acquisition_completed,
        &retry_data_dup_same_partition));

    ASSERT_PTR_EQUALS(test_data->retry_strategy, retry_data_dup_same_partition.retry_strategy);
    ASSERT_NOT_NULL(retry_data_dup_same_partition.retry_token);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, retry_data_dup_same_partition.token_acquisition_error_code);
    aws_mutex_unlock(&retry_data_dup_same_partition.mutex);

    /* should deduct 10 from capacity */
    aws_mutex_lock(&retry_data.mutex);
    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data.retry_token, AWS_RETRY_ERROR_TYPE_TRANSIENT, s_on_retry_ready, &retry_data));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_ready_completion_predicate, &retry_data));

    ASSERT_PTR_EQUALS(retry_data.retry_token, retry_data.schedule_token_value);
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);
    retry_data.schedule_retry_error_code = 0;
    retry_data.schedule_token_value = NULL;

    aws_mutex_unlock(&retry_data.mutex);

    /* should deduct 5 from capacity from a different token but the same partition */
    aws_mutex_lock(&retry_data_dup_same_partition.mutex);
    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data_dup_same_partition.retry_token,
        AWS_RETRY_ERROR_TYPE_SERVER_ERROR,
        s_on_retry_ready,
        &retry_data_dup_same_partition));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data_dup_same_partition.cvar,
        &retry_data_dup_same_partition.mutex,
        s_retry_ready_completion_predicate,
        &retry_data_dup_same_partition));

    ASSERT_PTR_EQUALS(retry_data_dup_same_partition.retry_token, retry_data_dup_same_partition.schedule_token_value);
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data_dup_same_partition.schedule_retry_error_code);
    retry_data_dup_same_partition.schedule_retry_error_code = 0;
    retry_data_dup_same_partition.schedule_token_value = NULL;

    /* this should fail. Partition capacity was 15, we've deducted 15 already, even though 3 retries were permitted. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_retry_ready, &retry_data));

    /* this should fail too even though it's a separate token, they're using the same bucket. Partition capacity was 15,
     * we've deducted 15 already, even though 3 retries were permitted. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data_dup_same_partition.retry_token,
            AWS_RETRY_ERROR_TYPE_SERVER_ERROR,
            s_on_retry_ready,
            &retry_data_dup_same_partition));

    aws_retry_token_release(retry_data_dup_same_partition.retry_token);
    aws_retry_token_release(retry_data.retry_token);

    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data_dup_same_partition.mutex));

    /* verify it doesn't affect other partitions */
    struct retry_data separate_partition = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&separate_partition.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        test_data->retry_strategy, NULL, s_on_retry_token_acquired, &separate_partition, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &separate_partition.cvar, &separate_partition.mutex, s_retry_token_acquisition_completed, &separate_partition));

    ASSERT_PTR_EQUALS(test_data->retry_strategy, separate_partition.retry_strategy);
    ASSERT_NOT_NULL(separate_partition.retry_token);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, separate_partition.token_acquisition_error_code);

    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        separate_partition.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_retry_ready, &separate_partition));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &separate_partition.cvar, &separate_partition.mutex, s_retry_ready_completion_predicate, &separate_partition));

    ASSERT_PTR_EQUALS(separate_partition.retry_token, separate_partition.schedule_token_value);
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, separate_partition.schedule_retry_error_code);

    aws_retry_token_release(separate_partition.retry_token);

    ASSERT_SUCCESS(aws_mutex_unlock(&separate_partition.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_standard_retry_strategy_failure_exhausts_bucket,
    s_fixture_setup,
    s_test_standard_retry_strategy_failure_exhausts_bucket,
    s_fixture_shutdown,
    &s_fixture_test_data);

static int s_test_standard_retry_strategy_failure_recovers(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;

    struct exponential_backoff_test_data *test_data = ctx;

    struct retry_data retry_data = {
        .mutex = AWS_MUTEX_INIT,
        .cvar = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_byte_cursor partition =
        aws_byte_cursor_from_c_str("us-west-2:elastic-something-something-manager-manager");

    ASSERT_SUCCESS(aws_mutex_lock(&retry_data.mutex));
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        test_data->retry_strategy, &partition, s_on_retry_token_acquired, &retry_data, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_token_acquisition_completed, &retry_data));

    ASSERT_PTR_EQUALS(test_data->retry_strategy, retry_data.retry_strategy);
    ASSERT_NOT_NULL(retry_data.retry_token);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, retry_data.token_acquisition_error_code);

    /* should deduct 10 from capacity */
    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data.retry_token, AWS_RETRY_ERROR_TYPE_TRANSIENT, s_on_retry_ready, &retry_data));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_ready_completion_predicate, &retry_data));

    ASSERT_PTR_EQUALS(retry_data.retry_token, retry_data.schedule_token_value);
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);
    retry_data.schedule_retry_error_code = 0;
    retry_data.schedule_token_value = NULL;

    /* should deduct 5 from capacity */
    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_retry_ready, &retry_data));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_ready_completion_predicate, &retry_data));

    ASSERT_PTR_EQUALS(retry_data.retry_token, retry_data.schedule_token_value);
    ASSERT_UINT_EQUALS(AWS_ERROR_SUCCESS, retry_data.schedule_retry_error_code);
    retry_data.schedule_retry_error_code = 0;
    retry_data.schedule_token_value = NULL;

    /* this should fail. Partition capacity was 15, we've deducted 15 already, even though 3 retries were permitted. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_retry_ready, &retry_data));

    aws_retry_token_release(retry_data.retry_token);

    int i = 0;
    /* pay back 5 of them */
    while (i < 5) {
        retry_data.token_acquisition_error_code = 0;
        retry_data.schedule_retry_error_code = 0;
        retry_data.schedule_token_value = NULL;
        retry_data.retry_token = NULL;

        /* acquire another token */
        ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
            test_data->retry_strategy, &partition, s_on_retry_token_acquired, &retry_data, 0));
        ASSERT_SUCCESS(aws_condition_variable_wait_pred(
            &retry_data.cvar, &retry_data.mutex, s_retry_token_acquisition_completed, &retry_data));

        ASSERT_SUCCESS(aws_retry_token_record_success(retry_data.retry_token));
        aws_retry_token_release(retry_data.retry_token);
        i++;
    }

    retry_data.token_acquisition_error_code = 0;
    retry_data.schedule_retry_error_code = 0;
    retry_data.schedule_token_value = NULL;
    retry_data.retry_token = NULL;

    /* acquire another token */
    ASSERT_SUCCESS(aws_retry_strategy_acquire_retry_token(
        test_data->retry_strategy, &partition, s_on_retry_token_acquired, &retry_data, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_token_acquisition_completed, &retry_data));

    /* should now succeed */
    ASSERT_SUCCESS(aws_retry_strategy_schedule_retry(
        retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_retry_ready, &retry_data));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &retry_data.cvar, &retry_data.mutex, s_retry_ready_completion_predicate, &retry_data));

    /* we only paid 5 back, make sure it fails again. */
    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED,
        aws_retry_strategy_schedule_retry(
            retry_data.retry_token, AWS_RETRY_ERROR_TYPE_SERVER_ERROR, s_on_retry_ready, &retry_data));

    aws_retry_token_release(retry_data.retry_token);
    ASSERT_SUCCESS(aws_mutex_unlock(&retry_data.mutex));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE_FIXTURE(
    test_standard_retry_strategy_failure_recovers,
    s_fixture_setup,
    s_test_standard_retry_strategy_failure_recovers,
    s_fixture_shutdown,
    &s_fixture_test_data);

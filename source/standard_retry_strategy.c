/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/logging.h>
#include <aws/io/retry_strategy.h>

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <inttypes.h>

AWS_STRING_FROM_LITERAL(s_empty_string, "");
static struct aws_byte_cursor s_empty_string_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("");
static const size_t s_initial_retry_bucket_capacity = 500u;
static const size_t s_standard_retry_cost = 5u;
static const size_t s_standard_transient_cost = 10u;
static const size_t s_standard_no_retry_cost = 1u;

struct retry_bucket {
    struct aws_allocator *allocator;
    struct aws_retry_strategy *owner;
    struct aws_string *partition_id;
    struct aws_byte_cursor partition_id_cur;
    size_t current_capacity;
    struct aws_mutex partition_lock;
};

struct retry_bucket_token {
    struct retry_bucket *strategy_bucket;
    struct aws_retry_token retry_token;
    struct aws_retry_token *exp_backoff_token;
    aws_retry_strategy_on_retry_token_acquired_fn *original_on_acquired;
    aws_retry_strategy_on_retry_ready_fn *original_on_ready;
    size_t last_retry_cost;
    void *original_user_data;
};

static bool s_partition_id_equals_byte_cur(const void *seated_cur, const void *cur_ptr) {
    return aws_byte_cursor_eq_ignore_case(seated_cur, cur_ptr);
}

static uint64_t s_hash_partition_id(const void *seated_partition_ptr) {
    return aws_hash_byte_cursor_ptr_ignore_case(seated_partition_ptr);
}

static void s_destroy_standard_retry_bucket(void *retry_bucket) {
    struct retry_bucket *standard_retry_bucket = retry_bucket;
    aws_retry_strategy_release(standard_retry_bucket->owner);
    aws_mutex_clean_up(&standard_retry_bucket->partition_lock);
    aws_mem_release(standard_retry_bucket->allocator, standard_retry_bucket);
}

struct standard_strategy {
    struct aws_retry_strategy base;
    struct aws_retry_strategy *exponential_backoff_retry_strategy;
    struct aws_hash_table token_buckets;
    size_t max_capacity;
    struct aws_mutex lock;
};

static void s_standard_retry_destroy(struct aws_retry_strategy *retry_strategy) {
    if (retry_strategy) {
        struct standard_strategy *standard_strategy = retry_strategy->impl;
        aws_retry_strategy_release(standard_strategy->exponential_backoff_retry_strategy);
        aws_hash_table_clean_up(&standard_strategy->token_buckets);
        aws_mutex_clean_up(&standard_strategy->lock);
        aws_mem_release(retry_strategy->allocator, standard_strategy);
    }
}

static void s_retry_bucket_destroy(void *bucket) {
    if (bucket) {
        struct retry_bucket *retry_bucket = bucket;

        aws_string_destroy(retry_bucket->partition_id);
        aws_mutex_clean_up(&retry_bucket->partition_lock);
        aws_retry_strategy_release(retry_bucket->owner);
        aws_mem_release(retry_bucket->allocator, retry_bucket);
    }
}

static void s_on_standard_retry_token_acquired(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)retry_strategy;
    (void)token;

    struct retry_bucket_token *retry_token = user_data;

    if (!error_code) {
        retry_token->exp_backoff_token = token;
        retry_token->original_on_acquired(
            retry_token->strategy_bucket->owner,
            error_code,
            &retry_token->retry_token,
            retry_token->original_user_data);
    } else {
        retry_token->original_on_acquired(
            retry_token->strategy_bucket->owner, error_code, NULL, retry_token->original_user_data);
        aws_retry_strategy_release_retry_token(&retry_token->retry_token);
    }
}

static int s_standard_retry_acquire_token(
    struct aws_retry_strategy *retry_strategy,
    const struct aws_byte_cursor *partition_id,
    aws_retry_strategy_on_retry_token_acquired_fn *on_acquired,
    void *user_data,
    uint64_t timeout_ms) {
    struct standard_strategy *standard_strategy = retry_strategy->impl;
    AWS_FATAL_ASSERT(!aws_mutex_lock(&standard_strategy->lock) && "Lock acquisition failed.");
    bool bucket_needs_cleanup = false;

    const struct aws_byte_cursor *partition_id_ptr =
        !partition_id || partition_id->len == 0 ? &s_empty_string_cur : partition_id;

    struct retry_bucket_token *token = aws_mem_calloc(retry_strategy->allocator, 1, sizeof(struct retry_bucket_token));
    if (!token) {
        return AWS_OP_ERR;
    }

    token->original_user_data = user_data;
    token->original_on_acquired = on_acquired;

    struct aws_hash_element *element_ptr;
    struct retry_bucket *bucket_ptr;
    if (aws_hash_table_find(&standard_strategy->token_buckets, partition_id_ptr, &element_ptr)) {
        bucket_ptr = aws_mem_calloc(standard_strategy->base.allocator, 1, sizeof(struct retry_bucket));

        if (!bucket_ptr) {
            goto error;
        }

        bucket_needs_cleanup = true;
        bucket_ptr->allocator = standard_strategy->base.allocator;
        bucket_ptr->partition_id = partition_id_ptr->len > 0
                                       ? aws_string_new_from_cursor(standard_strategy->base.allocator, partition_id)
                                       : (struct aws_string *)s_empty_string;

        if (!bucket_ptr->partition_id) {
            goto error;
        }

        bucket_ptr->partition_id_cur = aws_byte_cursor_from_string(bucket_ptr->partition_id);
        AWS_FATAL_ASSERT(!aws_mutex_init(&bucket_ptr->partition_lock) && "mutex init failed!");
        bucket_ptr->owner = retry_strategy;
        aws_retry_strategy_acquire(retry_strategy);
        bucket_ptr->current_capacity = standard_strategy->max_capacity;

        if (aws_hash_table_put(&standard_strategy->token_buckets, &bucket_ptr->partition_id_cur, bucket_ptr, NULL)) {
            goto error;
        }
        bucket_needs_cleanup = false;
    } else {
        bucket_ptr = element_ptr->value;
    }

    token->strategy_bucket = bucket_ptr;
    token->retry_token.retry_strategy = retry_strategy;
    aws_retry_strategy_acquire(retry_strategy);
    token->retry_token.allocator = retry_strategy->allocator;
    token->retry_token.impl = token;

    AWS_FATAL_ASSERT(!aws_mutex_lock(&bucket_ptr->partition_lock) && "mutex lock failed");
    /* this will sometimes be stale due to the way we're using it here, but the goal is just to provide
     * an early failure for the hot path, which this will do. */
    if (bucket_ptr->current_capacity == 0) {
        AWS_FATAL_ASSERT(!aws_mutex_unlock(&bucket_ptr->partition_lock) && "mutex unlock failed");
        aws_raise_error(AWS_IO_RETRY_PERMISSION_DENIED);
        goto table_updated;
    }
    bucket_ptr->current_capacity -= s_standard_no_retry_cost;
    token->last_retry_cost = s_standard_no_retry_cost;

    AWS_FATAL_ASSERT(!aws_mutex_unlock(&bucket_ptr->partition_lock) && "mutex unlock failed");

    if (aws_retry_strategy_acquire_retry_token(
            standard_strategy->exponential_backoff_retry_strategy,
            partition_id_ptr,
            s_on_standard_retry_token_acquired,
            token,
            timeout_ms)) {
        goto table_updated;
    }

    AWS_FATAL_ASSERT(!aws_mutex_unlock(&standard_strategy->lock) && "Mutex unlock failed");
    return AWS_OP_SUCCESS;

table_updated:
    aws_hash_table_remove(&standard_strategy->token_buckets, &bucket_ptr->partition_id_cur, NULL, NULL);
    bucket_needs_cleanup = false;

error:
    if (bucket_needs_cleanup) {
        s_retry_bucket_destroy(bucket_ptr);
    }

    aws_retry_strategy_release_retry_token(&token->retry_token);
    AWS_FATAL_ASSERT(!aws_mutex_unlock(&standard_strategy->lock) && "Mutex unlock failed");

    return AWS_OP_ERR;
}

void s_standard_retry_strategy_on_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)token;

    struct aws_retry_token *standard_retry_token = user_data;
    struct retry_bucket_token *impl = standard_retry_token->impl;
    impl->original_on_ready(standard_retry_token, error_code, impl->original_user_data);
}

static int s_standard_retry_strategy_schedule_retry(
    struct aws_retry_token *token,
    enum aws_retry_error_type error_type,
    aws_retry_strategy_on_retry_ready_fn *retry_ready,
    void *user_data) {

    if (error_type == AWS_RETRY_ERROR_TYPE_CLIENT_ERROR) {
        return aws_raise_error(AWS_IO_RETRY_PERMISSION_DENIED);
    }

    struct retry_bucket_token *impl = token->impl;

    size_t capacity_consumed = 0;

    AWS_FATAL_ASSERT(!aws_mutex_lock(&impl->strategy_bucket->partition_lock) && "mutex lock failed");
    size_t current_capacity = impl->strategy_bucket->current_capacity;
    if (current_capacity == 0) {
        AWS_FATAL_ASSERT(!aws_mutex_unlock(&impl->strategy_bucket->partition_lock) && "mutex lock failed");
        return aws_raise_error(AWS_IO_MAX_RETRIES_EXCEEDED);
    }

    if (error_type == AWS_RETRY_ERROR_TYPE_TRANSIENT) {
        capacity_consumed = aws_min_size(current_capacity, s_standard_transient_cost);
    } else {
        /* you may be looking for throttling, but if that happened, the service told us to slow down,
         * but is otherwise healthy. Pay a smaller penalty for those. */
        capacity_consumed = aws_min_size(current_capacity, s_standard_retry_cost);
    }

    impl->original_user_data = user_data;
    impl->original_on_ready = retry_ready;

    int err_code = aws_retry_strategy_schedule_retry(
        impl->exp_backoff_token, error_type, s_standard_retry_strategy_on_retry_ready, token);
    if (!err_code) {
        impl->last_retry_cost = capacity_consumed;
        impl->strategy_bucket -= capacity_consumed;
    }

    AWS_FATAL_ASSERT(!aws_mutex_unlock(&impl->strategy_bucket->partition_lock) && "mutex unlock failed");
    return err_code;
}

static int s_standard_retry_strategy_record_success(struct aws_retry_token *token) {
    struct retry_bucket_token *impl = token->impl;

    AWS_FATAL_ASSERT(!aws_mutex_lock(&impl->strategy_bucket->partition_lock) && "mutex lock failed");
    impl->strategy_bucket->current_capacity += impl->last_retry_cost;
    impl->last_retry_cost = 0;
    AWS_FATAL_ASSERT(!aws_mutex_unlock(&impl->strategy_bucket->partition_lock) && "mutex unlock failed");
    return AWS_OP_SUCCESS;
}

static void s_standard_retry_strategy_release_token(struct aws_retry_token *token) {
    if (token) {
        struct retry_bucket_token *impl = token->impl;
        if (impl->exp_backoff_token) {
            aws_retry_strategy_release_retry_token(impl->exp_backoff_token);
        }
        aws_retry_strategy_release(token->retry_strategy);
        aws_mem_release(token->allocator, token);
    }
}

static struct aws_retry_strategy_vtable s_standard_retry_vtable = {
    .schedule_retry = s_standard_retry_strategy_schedule_retry,
    .acquire_token = s_standard_retry_acquire_token,
    .release_token = s_standard_retry_strategy_release_token,
    .destroy = s_standard_retry_destroy,
    .record_success = s_standard_retry_strategy_record_success,
};

struct aws_retry_strategy *aws_retry_strategy_new_standard(
    struct aws_allocator *allocator,
    const struct aws_standard_retry_options *config) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(config);

    struct standard_strategy *standard_strategy = aws_mem_calloc(allocator, 1, sizeof(struct standard_strategy));

    if (!standard_strategy) {
        return NULL;
    }

    aws_atomic_init_int(&standard_strategy->base.ref_count, 1);

    struct aws_exponential_backoff_retry_options config_cpy = config->backoff_retry_options;

    /* standard default is 3. */
    if (!config->backoff_retry_options.max_retries) {
        config_cpy.max_retries = 3;
    }

    standard_strategy->exponential_backoff_retry_strategy =
        aws_retry_strategy_new_exponential_backoff(allocator, &config_cpy);

    if (!standard_strategy->exponential_backoff_retry_strategy) {
        goto error;
    }

    if (aws_hash_table_init(
            &standard_strategy->token_buckets,
            allocator,
            16u,
            s_hash_partition_id,
            s_partition_id_equals_byte_cur,
            NULL,
            s_destroy_standard_retry_bucket)) {
        goto error;
    }

    standard_strategy->max_capacity =
        config->initial_bucket_capacity ? config->initial_bucket_capacity : s_initial_retry_bucket_capacity;

    AWS_FATAL_ASSERT(!aws_mutex_init(&standard_strategy->lock) && "mutex init failed");

    standard_strategy->base.vtable = &s_standard_retry_vtable;
    return &standard_strategy->base;

error:
    if (standard_strategy->exponential_backoff_retry_strategy) {
        aws_retry_strategy_release(standard_strategy->exponential_backoff_retry_strategy);
    }

    aws_mem_release(allocator, standard_strategy);

    return NULL;
}

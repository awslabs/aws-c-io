/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/retry_strategy.h>

#include <aws/io/private/rate_limiter.h>

#include <aws/common/hash_table.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <inttypes.h>

/*
 * Adaptive retry strategy: "standard mode plus client-side rate limiting".
 *
 * Composes a standard strategy exactly as the standard strategy composes exponential-backoff, delegating all
 * quota/backoff/max-attempts behavior to it, and layers two hooks on top driven by rate_limiter.c:
 *   - GetSendToken: a token-bucket gate run before each send (acquire + retry-ready). When the limiter reports
 *     a wait, the send is DEFERRED on an event loop ; if fast_fail_if_no_token is set, the
 *     send fails fast with AWS_IO_RETRY_PERMISSION_DENIED instead of waiting.
 *   - Bookkeeping: _UpdateClientSendingRate run after each response. A throttling response decreases the rate
 *     and enables the limiter (schedule_retry with AWS_RETRY_ERROR_TYPE_THROTTLING). Every other RECEIVED
 *     response grows the rate along the CUBIC curve: a success (record_success) and the retryable received
 *     errors SERVER_ERROR / CLIENT_ERROR (schedule_retry). TRANSIENT errors do not affect the rate limiter
 *
 * Each partition_id gets its own rate limiter bucket (like standard's retry quota buckets), created disabled on first
 * use, so a throttle on one partition does not pace sends to another. The rate limiter is a single-threaded state
 * machine; each bucket's lock is taken around every limiter call so capacity is never observed < 0 across threads.
 *
 * The event loop used for deferral comes from the el_group the caller already supplies for the backoff layer
 * (config->standard_options.backoff_retry_options.el_group). No new config and no reach into standard's
 * internals: this mirrors how exponential_backoff_retry_strategy.c defers its own retries.
 */

/* REQUEST_COST: every send costs exactly one token. */
static const double s_adaptive_request_cost = 1.0;

/* NULL or empty partition_id maps to this shared key. */
static const struct aws_byte_cursor s_empty_partition_cur = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("");

/* One rate limiter per partition_id, so a throttle on one partition does not slow sends to another. */
struct adaptive_retry_bucket {
    struct aws_allocator *allocator;
    struct aws_retry_strategy *owner;
    struct aws_string *partition_id;
    struct aws_byte_cursor partition_id_cur;
    struct {
        /* This partition's sending rate (token bucket + CUBIC); off until its first throttle. */
        struct aws_rate_limiter_token_bucket limiter;
        /* rate_limiter.c is single-threaded, so every limiter call takes this lock. */
        struct aws_mutex partition_lock;
    } synced_data;
};

struct adaptive_strategy {
    struct aws_retry_strategy base;
    struct aws_retry_strategy *standard_strategy;
    struct aws_event_loop_group *el_group;
    bool fast_fail_if_no_token;
    struct {
        /* partition_id -> adaptive_retry_bucket; the lock guards the table only. */
        struct aws_hash_table token_buckets;
        struct aws_mutex lock;
    } synced_data;
};

struct adaptive_retry_token {
    struct aws_retry_token base;
    struct adaptive_retry_bucket *strategy_bucket;
    struct aws_retry_token *standard_token;
    struct aws_event_loop *bound_loop;
    struct aws_task gate_task;

    enum adaptive_retry_token_phase {
        ADAPTIVE_RETRY_TOKEN_PHASE_ACQUIRING, /* on_acquired pending; we own the creation ref */
        ADAPTIVE_RETRY_TOKEN_PHASE_RETRYING,  /* caller owns the token; on_ready used for retries */
    } phase;

    union {
        /* data for ADAPTIVE_RETRY_TOKEN_PHASE_ACQUIRING */
        struct {
            aws_retry_strategy_on_retry_token_acquired_fn *on_acquired;
            void *user_data;
        } acquiring;

        /* data for ADAPTIVE_RETRY_TOKEN_PHASE_RETRYING */
        struct {
            aws_retry_strategy_on_retry_ready_fn *on_ready;
            void *user_data;
        } retrying;
    } u;
};

static bool s_partition_id_equals_byte_cur(const void *seated_cur, const void *cur_ptr) {
    return aws_byte_cursor_eq_ignore_case(seated_cur, cur_ptr);
}

static uint64_t s_hash_partition_id(const void *seated_partition_ptr) {
    return aws_hash_byte_cursor_ptr_ignore_case(seated_partition_ptr);
}

/* Hash table destroy callback; also used when a new bucket fails to insert. */
static void s_destroy_adaptive_retry_bucket(void *retry_bucket) {
    struct adaptive_retry_bucket *bucket = retry_bucket;
    AWS_LOGF_TRACE(
        AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
        "id=%p: destroying rate limiter bucket for partition_id " PRInSTR,
        (void *)bucket->owner,
        AWS_BYTE_CURSOR_PRI(bucket->partition_id_cur));
    aws_string_destroy(bucket->partition_id);
    aws_mutex_clean_up(&bucket->synced_data.partition_lock);
    aws_mem_release(bucket->allocator, bucket);
}

/* New bucket for partition_id; its limiter starts disabled until this partition's first throttle. */
static struct adaptive_retry_bucket *s_adaptive_retry_bucket_new(
    struct adaptive_strategy *strategy,
    const struct aws_byte_cursor *partition_id) {

    struct adaptive_retry_bucket *bucket =
        aws_mem_calloc(strategy->base.allocator, 1, sizeof(struct adaptive_retry_bucket));
    bucket->allocator = strategy->base.allocator;
    bucket->owner = &strategy->base;
    bucket->partition_id = aws_string_new_from_cursor(bucket->allocator, partition_id);
    bucket->partition_id_cur = aws_byte_cursor_from_string(bucket->partition_id);
    AWS_FATAL_ASSERT(!aws_mutex_init(&bucket->synced_data.partition_lock) && "mutex init failed");
    aws_rate_limiter_token_bucket_init(&bucket->synced_data.limiter);
    return bucket;
}

/* Finds the bucket for partition_id, creating it on first use. Returns NULL if the table insert fails. */
static struct adaptive_retry_bucket *s_get_or_create_bucket(
    struct adaptive_strategy *strategy,
    const struct aws_byte_cursor *partition_id) {

    const struct aws_byte_cursor *partition_id_ptr =
        !partition_id || partition_id->len == 0 ? &s_empty_partition_cur : partition_id;

    struct adaptive_retry_bucket *bucket = NULL;
    struct aws_hash_element *element = NULL;

    /* Table lock only; each bucket's own lock guards its limiter. */
    aws_mutex_lock(&strategy->synced_data.lock);
    aws_hash_table_find(&strategy->synced_data.token_buckets, partition_id_ptr, &element);
    if (element) {
        /* Seen before: every token for this partition shares this one bucket. */
        bucket = element->value;
        AWS_LOGF_TRACE(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: reusing rate limiter bucket for partition_id " PRInSTR,
            (void *)&strategy->base,
            AWS_BYTE_CURSOR_PRI(*partition_id_ptr));
    } else {
        /* First token for this partition. The key points into the bucket's own string, so it lives as long. */
        bucket = s_adaptive_retry_bucket_new(strategy, partition_id_ptr);
        if (aws_hash_table_put(&strategy->synced_data.token_buckets, &bucket->partition_id_cur, bucket, NULL)) {
            s_destroy_adaptive_retry_bucket(bucket);
            bucket = NULL;
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
                "id=%p: created rate limiter bucket for partition_id " PRInSTR,
                (void *)&strategy->base,
                AWS_BYTE_CURSOR_PRI(*partition_id_ptr));
        }
    }
    aws_mutex_unlock(&strategy->synced_data.lock);

    return bucket;
}

/* Runs the GetSendToken gate under the partition lock. Returns the number of ns the caller must wait (0 = now). */
static uint64_t s_rate_limiter_acquire(struct adaptive_retry_bucket *bucket) {
    aws_mutex_lock(&bucket->synced_data.partition_lock);
    uint64_t wait_ns = aws_rate_limiter_token_bucket_acquire(&bucket->synced_data.limiter, s_adaptive_request_cost);
    aws_mutex_unlock(&bucket->synced_data.partition_lock);
    return wait_ns;
}

/* Runs _UpdateClientSendingRate under the partition lock: throttle lowers the rate, other responses raise it. */
static void s_rate_limiter_update(struct adaptive_retry_bucket *bucket, bool is_throttling_error) {
    aws_mutex_lock(&bucket->synced_data.partition_lock);
    aws_rate_limiter_token_bucket_update_sending_rate(&bucket->synced_data.limiter, is_throttling_error);
    if (is_throttling_error) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: partition_id " PRInSTR " throttled; fill_rate lowered to %.2f req/s, limiter on",
            (void *)bucket->owner,
            AWS_BYTE_CURSOR_PRI(bucket->partition_id_cur),
            bucket->synced_data.limiter.fill_rate);
    } else {
        AWS_LOGF_TRACE(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: partition_id " PRInSTR " response received; fill_rate now %.2f req/s, limiter %s",
            (void *)bucket->owner,
            AWS_BYTE_CURSOR_PRI(bucket->partition_id_cur),
            bucket->synced_data.limiter.fill_rate,
            bucket->synced_data.limiter.enabled ? "on" : "off");
    }
    aws_mutex_unlock(&bucket->synced_data.partition_lock);
}

/* Fires on_acquired while acquiring, otherwise on_ready. */
static void s_fire_gate_callback(struct adaptive_retry_token *token, int error_code) {
    switch (token->phase) {
        case ADAPTIVE_RETRY_TOKEN_PHASE_ACQUIRING:
            /* First send: the caller is still waiting for its token */
            if (!error_code) {
                /* Ownership moves to the caller; flip first, the callback may release or retry the token. */
                token->phase = ADAPTIVE_RETRY_TOKEN_PHASE_RETRYING;
                token->u.acquiring.on_acquired(
                    token->base.retry_strategy, error_code, &token->base, token->u.acquiring.user_data);
            } else {
                /* Acquire failed: the caller gets NULL instead of token. */
                token->u.acquiring.on_acquired(
                    token->base.retry_strategy, error_code, NULL, token->u.acquiring.user_data);
                /* Caller got NULL and can't release it, so drop the creation ref. */
                aws_retry_token_release(&token->base);
            }
            break;
        case ADAPTIVE_RETRY_TOKEN_PHASE_RETRYING:
            /* Retry: the caller already owns the token, so only report the result. */
            token->u.retrying.on_ready(&token->base, error_code, token->u.retrying.user_data);
            break;
    }
}

/* The gate task re-runs the gate through this after its wait. */
static void s_apply_gate(struct adaptive_retry_token *token);

/* Re-runs the gate at the real send time, so the debit happens then and capacity never goes below zero. */
static void s_adaptive_gate_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct adaptive_retry_token *token = arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        /* Grants now, or schedules a new task that takes its own ref. */
        s_apply_gate(token);
    } else {
        /* Event loop shutting down: deliver cancellation. */
        s_fire_gate_callback(token, AWS_ERROR_IO_OPERATION_CANCELLED);
    }

    /* Drop the ref taken when this task was scheduled. */
    aws_retry_token_release(&token->base);
}

/* Schedules the gate task wait_ns out, holding a ref until the task runs. */
static void s_schedule_gate_task(struct adaptive_retry_token *token, uint64_t wait_ns) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
        "id=%p: partition_id " PRInSTR " has no token; pacing send by %" PRIu64 " ns",
        (void *)token->base.retry_strategy,
        AWS_BYTE_CURSOR_PRI(token->strategy_bucket->partition_id_cur),
        wait_ns);

    aws_task_init(&token->gate_task, s_adaptive_gate_task, token, "aws_adaptive_retry_gate_task");

    uint64_t current_time = 0;
    aws_event_loop_current_clock_time(token->bound_loop, &current_time);

    /* Hold the token until the task runs. */
    aws_retry_token_acquire(&token->base);
    aws_event_loop_schedule_task_future(token->bound_loop, &token->gate_task, current_time + wait_ns);
}

/*
 * Applies the gate result: grant now, fast-fail, or defer-and-re-acquire after the wait.
 */
static void s_apply_gate(struct adaptive_retry_token *token) {
    struct adaptive_strategy *strategy = token->base.retry_strategy->impl;

    /* Take one token from this token's partition bucket; a limiter that is still off always grants. */
    uint64_t wait_ns = s_rate_limiter_acquire(token->strategy_bucket);

    if (wait_ns == 0) {
        /* Granted and debited: proceed. */
        s_fire_gate_callback(token, AWS_OP_SUCCESS);
        return;
    }

    /* wait_ns != 0: no token available yet, nothing debited; fast-fail or wait wait_ns. */
    if (strategy->fast_fail_if_no_token) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: partition_id " PRInSTR " has no token and fast-fail is set; denying send",
            (void *)token->base.retry_strategy,
            AWS_BYTE_CURSOR_PRI(token->strategy_bucket->partition_id_cur));
        aws_raise_error(AWS_IO_RETRY_PERMISSION_DENIED);
        /* Nothing was debited. */
        s_fire_gate_callback(token, AWS_IO_RETRY_PERMISSION_DENIED);
        return;
    }

    /* Defer; the debit happens when the re-acquire grants. */
    s_schedule_gate_task(token, wait_ns);
}

static void s_adaptive_retry_destroy(struct aws_retry_strategy *retry_strategy) {
    AWS_LOGF_TRACE(AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY, "id=%p: destroying adaptive strategy", (void *)retry_strategy);
    struct adaptive_strategy *strategy = retry_strategy->impl;
    struct aws_event_loop_group *el_group = strategy->el_group;
    aws_retry_strategy_release(strategy->standard_strategy);
    /* Frees every partition bucket through s_destroy_adaptive_retry_bucket. */
    aws_hash_table_clean_up(&strategy->synced_data.token_buckets);
    aws_mutex_clean_up(&strategy->synced_data.lock);
    aws_mem_release(retry_strategy->allocator, strategy);
    aws_event_loop_group_release(el_group);
}

/*
 * Trampoline for the inner standard strategy's token acquisition. Seats the inner token on our wrapper token,
 * then applies the GetSendToken gate (which fires the caller's on_acquired, immediately or deferred).
 */
static void s_on_standard_token_acquired(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)retry_strategy;

    struct adaptive_retry_token *adaptive_token = user_data;

    if (!error_code) {
        adaptive_token->standard_token = token;
        /* GetSendToken gate: fires on_acquired (immediately, deferred, or fast-failed). */
        s_apply_gate(adaptive_token);
    } else {
        /* Inner acquisition failed; the limiter is not consulted. Propagate the error straight through. */
        s_fire_gate_callback(adaptive_token, error_code);
    }
}

static int s_adaptive_retry_acquire_token(
    struct aws_retry_strategy *retry_strategy,
    const struct aws_byte_cursor *partition_id,
    aws_retry_strategy_on_retry_token_acquired_fn *on_acquired,
    void *user_data,
    uint64_t timeout_ms) {

    struct adaptive_strategy *strategy = retry_strategy->impl;

    /* Find this partition's bucket, created on first use and shared by every later token for it. */
    struct adaptive_retry_bucket *bucket = s_get_or_create_bucket(strategy, partition_id);
    if (!bucket) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: adaptive strategy failed to create rate limiter bucket: %s",
            (void *)retry_strategy,
            aws_error_debug_str(aws_last_error()));
        return AWS_OP_ERR;
    }

    struct adaptive_retry_token *token =
        aws_mem_calloc(retry_strategy->allocator, 1, sizeof(struct adaptive_retry_token));

    /* Every gate check and rate update for this token goes to this bucket. */
    token->strategy_bucket = bucket;
    token->phase = ADAPTIVE_RETRY_TOKEN_PHASE_ACQUIRING;
    token->u.acquiring.on_acquired = on_acquired;
    token->u.acquiring.user_data = user_data;
    token->base.retry_strategy = retry_strategy;
    token->base.allocator = retry_strategy->allocator;
    token->base.impl = token;
    token->bound_loop = aws_event_loop_group_get_next_loop(strategy->el_group);
    aws_atomic_init_int(&token->base.ref_count, 1u);
    aws_retry_strategy_acquire(retry_strategy);

    if (aws_retry_strategy_acquire_retry_token(
            strategy->standard_strategy, partition_id, s_on_standard_token_acquired, token, timeout_ms)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: adaptive strategy failed to acquire token from backing standard strategy: %s",
            (void *)retry_strategy,
            aws_error_debug_str(aws_last_error()));
        aws_retry_token_release(&token->base);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Trampoline for the inner standard strategy's retry-ready. Applies the GetSendToken gate before the retry
 * send, firing the caller's retry_ready immediately or deferred.
 */
static void s_on_standard_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)token;

    struct aws_retry_token *adaptive_retry_token = user_data;
    struct adaptive_retry_token *impl = adaptive_retry_token->impl;

    if (!error_code) {
        /* GetSendToken gate before the retry: fires on_ready (immediately, deferred, or fast-failed). */
        s_apply_gate(impl);
    } else {
        /* Inner retry was cancelled/failed; propagate straight through without consulting the limiter. */
        impl->u.retrying.on_ready(adaptive_retry_token, error_code, impl->u.retrying.user_data);
    }

    /* release the acquire we did before scheduling the retry on the inner strategy. */
    aws_retry_token_release(adaptive_retry_token);
}

static int s_adaptive_retry_schedule_retry(
    struct aws_retry_token *token,
    enum aws_retry_error_type error_type,
    aws_retry_strategy_on_retry_ready_fn *retry_ready,
    void *user_data) {

    struct adaptive_retry_token *impl = token->impl;

    /* Retries are only possible once the caller owns the token. */
    AWS_ASSERT(impl->phase == ADAPTIVE_RETRY_TOKEN_PHASE_RETRYING);

    /*
     * Bookkeeping (_UpdateClientSendingRate) runs whenever a response is RECEIVED from the service, before the
     * inner strategy decides whether to schedule the retry, because the response happened either way.
     *
     * The update is binary on a received response: a THROTTLING response takes the throttle branch (rate
     * down + enable the limiter); every OTHER received response takes the success/growth branch
     * (_UpdateMeasuredRate + the CUBIC _CUBICSuccess climb). SERVER_ERROR and CLIENT_ERROR are received
     * responses, so they grow the rate just like a success does. TRANSIENT_ERROR does not affect the rate limiter
     */
    if (error_type == AWS_RETRY_ERROR_TYPE_THROTTLING) {
        s_rate_limiter_update(impl->strategy_bucket, true /*is_throttling_error*/);
    } else if (error_type != AWS_RETRY_ERROR_TYPE_TRANSIENT) {
        s_rate_limiter_update(impl->strategy_bucket, false /*is_throttling_error*/);
    }

    impl->u.retrying.on_ready = retry_ready;
    impl->u.retrying.user_data = user_data;

    /* acquire before scheduling to prevent clean up before the scheduled task runs. */
    aws_retry_token_acquire(&impl->base);
    if (aws_retry_strategy_schedule_retry(impl->standard_token, error_type, s_on_standard_retry_ready, token)) {
        /* release for the above acquire */
        aws_retry_token_release(&impl->base);
        AWS_LOGF_ERROR(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "token_id=%p: adaptive strategy error scheduling retry on backing standard strategy: %s",
            (void *)token,
            aws_error_debug_str(aws_last_error()));
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_adaptive_retry_record_success(struct aws_retry_token *token) {
    struct adaptive_retry_token *impl = token->impl;

    /* Bookkeeping: a successful response grows the allowed rate along the CUBIC curve (no-op while disabled). */
    s_rate_limiter_update(impl->strategy_bucket, false /*is_throttling_error*/);

    return aws_retry_token_record_success(impl->standard_token);
}

static void s_adaptive_retry_release_token(struct aws_retry_token *token) {
    if (token) {
        AWS_LOGF_TRACE(AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY, "id=%p: releasing adaptive token", (void *)token);
        struct adaptive_retry_token *impl = token->impl;
        aws_retry_token_release(impl->standard_token);
        aws_retry_strategy_release(token->retry_strategy);
        aws_mem_release(token->allocator, impl);
    }
}

static struct aws_retry_strategy_vtable s_adaptive_retry_vtable = {
    .schedule_retry = s_adaptive_retry_schedule_retry,
    .acquire_token = s_adaptive_retry_acquire_token,
    .release_token = s_adaptive_retry_release_token,
    .destroy = s_adaptive_retry_destroy,
    .record_success = s_adaptive_retry_record_success,
};

struct aws_retry_strategy *aws_retry_strategy_new_adaptive(
    struct aws_allocator *allocator,
    const struct aws_adaptive_retry_options *config) {
    AWS_PRECONDITION(allocator);
    AWS_PRECONDITION(config);
    if (!config->standard_options.backoff_retry_options.el_group) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    AWS_LOGF_INFO(AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY, "static: creating new adaptive retry strategy");

    struct adaptive_strategy *strategy = aws_mem_calloc(allocator, 1, sizeof(struct adaptive_strategy));

    aws_atomic_init_int(&strategy->base.ref_count, 1);

    strategy->standard_strategy = aws_retry_strategy_new_standard(allocator, &config->standard_options);
    if (!strategy->standard_strategy) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: allocation of backing standard retry strategy failed: %s",
            (void *)&strategy->base,
            aws_error_debug_str(aws_last_error()));
        goto error;
    }

    /* partition_id -> bucket, case-insensitive like standard's retry quota table. */
    if (aws_hash_table_init(
            &strategy->synced_data.token_buckets,
            allocator,
            16u,
            s_hash_partition_id,
            s_partition_id_equals_byte_cur,
            NULL,
            s_destroy_adaptive_retry_bucket)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: rate limiter bucket table creation failed: %s",
            (void *)&strategy->base,
            aws_error_debug_str(aws_last_error()));
        goto error;
    }

    strategy->el_group = aws_event_loop_group_acquire(config->standard_options.backoff_retry_options.el_group);
    strategy->fast_fail_if_no_token = config->fast_fail_if_no_token;
    AWS_FATAL_ASSERT(!aws_mutex_init(&strategy->synced_data.lock) && "mutex init failed");

    strategy->base.allocator = allocator;
    strategy->base.vtable = &s_adaptive_retry_vtable;
    strategy->base.impl = strategy;
    return &strategy->base;

error:
    if (strategy->standard_strategy) {
        aws_retry_strategy_release(strategy->standard_strategy);
    }
    aws_mem_release(allocator, strategy);
    return NULL;
}

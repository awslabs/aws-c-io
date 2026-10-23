/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/retry_strategy.h>

#include <aws/io/private/rate_limiter.h>

#include <aws/common/clock.h>
#include <aws/common/hash_table.h>
#include <aws/common/linked_list.h>
#include <aws/common/math.h>
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
 * Sends that must wait join their bucket's pending_tokens and are served in arrival order by one scheduling task per
 * bucket; timeout_ms from acquire bounds each wait (0 = no limit).
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
    /* Event loop that runs scheduling_task for this partition. */
    struct aws_event_loop *bound_loop;
    struct {
        /* This partition's sending rate (token bucket + CUBIC); off until its first throttle. */
        struct aws_rate_limiter_token_bucket limiter;
        /* Requests waiting for the rate limiter to let them send, oldest first. */
        struct aws_linked_list pending_tokens;
        /* Lets waiting requests send in order; scheduled whenever pending_tokens is not empty. */
        struct aws_task scheduling_task;
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

    /* How long this request may wait to send (timeout_ms from acquire, in ns); 0 means no limit. */
    uint64_t max_wait_time_ns;
    /* Time when the current wait gives up (start of wait + max_wait_time_ns); 0 means it never gives up. */
    uint64_t max_permissible_delay_ns;
    /* Links this request into its bucket's pending_tokens while it waits. */
    struct aws_linked_list_node pending_node;

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
    /* Tokens hold a strategy ref, so no token can still be pending here. */
    AWS_ASSERT(aws_linked_list_empty(&bucket->synced_data.pending_tokens));
    aws_string_destroy(bucket->partition_id);
    aws_mutex_clean_up(&bucket->synced_data.partition_lock);
    aws_mem_release(bucket->allocator, bucket);
}

/* Each bucket's scheduling_task runs this. */
static void s_schedule_pending_tokens(struct aws_task *task, void *arg, enum aws_task_status status);

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
    bucket->bound_loop = aws_event_loop_group_get_next_loop(strategy->el_group);
    aws_task_init(
        &bucket->synced_data.scheduling_task, s_schedule_pending_tokens, bucket, "aws_adaptive_retry_scheduling_task");
    aws_linked_list_init(&bucket->synced_data.pending_tokens);
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

/* Result of the GetSendToken gate, decided under the partition lock. */
enum adaptive_gate_result {
    ADAPTIVE_GATE_GRANTED, /* took a send token */
    ADAPTIVE_GATE_DENIED,  /* no send token and fast-fail is set */
    ADAPTIVE_GATE_WAITING, /* joined pending_tokens; scheduling_task fires the callback later */
};

/* Puts the request at the back of pending_tokens; if the list was empty, schedules the task too. Lock held. */
static void s_join_pending_tokens(struct adaptive_retry_token *token, uint64_t wait_ns, bool list_was_empty) {
    struct adaptive_retry_bucket *bucket = token->strategy_bucket;

    AWS_LOGF_TRACE(
        AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
        "id=%p: partition_id " PRInSTR " has no token; waiting to send",
        (void *)token->base.retry_strategy,
        AWS_BYTE_CURSOR_PRI(bucket->partition_id_cur));

    /* Start this wait's timeout clock; a deadline of 0 means no timeout. */
    uint64_t current_time = 0;
    aws_event_loop_current_clock_time(bucket->bound_loop, &current_time);
    token->max_permissible_delay_ns = 0;
    if (token->max_wait_time_ns > 0) {
        token->max_permissible_delay_ns = aws_add_u64_saturating(current_time, token->max_wait_time_ns);
    }

    /* Hold a ref while the request waits; s_fire_pending_callbacks drops it. */
    aws_retry_token_acquire(&token->base);
    aws_linked_list_push_back(&bucket->synced_data.pending_tokens, &token->pending_node);

    if (list_was_empty) {
        /* No task is scheduled yet: run it when the next send token is ready, or at the deadline if sooner. */
        uint64_t schedule_at = aws_add_u64_saturating(current_time, wait_ns);
        if (token->max_permissible_delay_ns != 0) {
            schedule_at = aws_min_u64(schedule_at, token->max_permissible_delay_ns);
        }
        aws_event_loop_schedule_task_future(bucket->bound_loop, &bucket->synced_data.scheduling_task, schedule_at);
    }
}

/* Runs the GetSendToken gate; the check and the join happen under one lock, so nothing changes in between. */
static enum adaptive_gate_result s_rate_limiter_acquire(struct adaptive_retry_token *token, bool fast_fail) {
    struct adaptive_retry_bucket *bucket = token->strategy_bucket;
    enum adaptive_gate_result result = ADAPTIVE_GATE_WAITING;

    aws_mutex_lock(&bucket->synced_data.partition_lock);
    bool list_was_empty = aws_linked_list_empty(&bucket->synced_data.pending_tokens);
    uint64_t wait_ns = 0;
    if (list_was_empty) {
        /* Nobody is waiting: try to take a send token now. */
        wait_ns = aws_rate_limiter_token_bucket_acquire(&bucket->synced_data.limiter, s_adaptive_request_cost);
    }

    if (list_was_empty && wait_ns == 0) {
        /* Granted and debited. */
        result = ADAPTIVE_GATE_GRANTED;
    } else if (fast_fail) {
        /* No send token and fast-fail is set; nothing was debited. */
        result = ADAPTIVE_GATE_DENIED;
    } else {
        /* Others are waiting or no send token yet: join the back, so nobody sends ahead of an earlier request. */
        s_join_pending_tokens(token, wait_ns, list_was_empty);
    }
    aws_mutex_unlock(&bucket->synced_data.partition_lock);

    return result;
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

/* Tells each request in the list its result, then drops the ref it held while waiting. */
static void s_fire_pending_callbacks(struct aws_linked_list *tokens, int error_code) {
    while (!aws_linked_list_empty(tokens)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(tokens);
        struct adaptive_retry_token *token = AWS_CONTAINER_OF(node, struct adaptive_retry_token, pending_node);
        s_fire_gate_callback(token, error_code);
        aws_retry_token_release(&token->base);
    }
}

/* Scheduling task: lets waiting requests send in arrival order and fails the ones past their timeout. */
static void s_schedule_pending_tokens(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct adaptive_retry_bucket *bucket = arg;
    struct aws_linked_list *pending_tokens = &bucket->synced_data.pending_tokens;

    /* Collect results here; their callbacks fire after the lock is released. */
    struct aws_linked_list granted_tokens;
    struct aws_linked_list failed_tokens;
    aws_linked_list_init(&granted_tokens);
    aws_linked_list_init(&failed_tokens);
    int failed_error_code = AWS_IO_RETRY_PERMISSION_DENIED;

    uint64_t current_time = 0;
    aws_event_loop_current_clock_time(bucket->bound_loop, &current_time);

    aws_mutex_lock(&bucket->synced_data.partition_lock);
    if (status != AWS_TASK_STATUS_RUN_READY) {
        /* Event loop is shutting down: cancel every waiting request. */
        aws_linked_list_swap_contents(pending_tokens, &failed_tokens);
        failed_error_code = AWS_ERROR_IO_OPERATION_CANCELLED;
    } else {
        /* When this task runs next: the next send token or the earliest deadline, whichever comes first. */
        uint64_t reschedule_at = UINT64_MAX;
        /* True until the limiter runs out of send tokens in this pass. */
        bool capacity_left = true;

        /* Walk the waiting requests from oldest to newest. */
        struct aws_linked_list_node *node = aws_linked_list_begin(pending_tokens);
        while (node != aws_linked_list_end(pending_tokens)) {
            struct aws_linked_list_node *next = aws_linked_list_next(node);
            struct adaptive_retry_token *token = AWS_CONTAINER_OF(node, struct adaptive_retry_token, pending_node);

            if (capacity_left) {
                uint64_t wait_ns =
                    aws_rate_limiter_token_bucket_acquire(&bucket->synced_data.limiter, s_adaptive_request_cost);
                if (wait_ns == 0) {
                    /* The limiter lets this request send: move it to granted_tokens. */
                    aws_linked_list_remove(node);
                    aws_linked_list_push_back(&granted_tokens, node);
                    node = next;
                    continue;
                }
                /* No send token left: everyone behind this request keeps waiting too, so the order holds. */
                capacity_left = false;
                reschedule_at = aws_add_u64_saturating(current_time, wait_ns);
            }

            if (token->max_permissible_delay_ns != 0 && current_time >= token->max_permissible_delay_ns) {
                /* Waited longer than its timeout_ms: move it to failed_tokens. */
                aws_linked_list_remove(node);
                aws_linked_list_push_back(&failed_tokens, node);
            } else if (token->max_permissible_delay_ns != 0) {
                /* Still within its timeout: make sure this task runs again by its deadline. */
                reschedule_at = aws_min_u64(reschedule_at, token->max_permissible_delay_ns);
            }
            node = next;
        }

        if (!aws_linked_list_empty(pending_tokens)) {
            /* Requests are still waiting: run again at reschedule_at. */
            aws_event_loop_schedule_task_future(
                bucket->bound_loop, &bucket->synced_data.scheduling_task, reschedule_at);
        }
    }
    aws_mutex_unlock(&bucket->synced_data.partition_lock);

    /* Fire callbacks outside the lock, since a callback can call back into the strategy. */
    /* Don't touch bucket after this: the last release can destroy the strategy and its buckets. */
    s_fire_pending_callbacks(&granted_tokens, AWS_ERROR_SUCCESS);
    s_fire_pending_callbacks(&failed_tokens, failed_error_code);
}

/*
 * Applies the gate result: grant now, fast-fail, or wait in pending_tokens.
 */
static void s_apply_gate(struct adaptive_retry_token *token) {
    struct adaptive_strategy *strategy = token->base.retry_strategy->impl;

    /* Take one token from this token's partition bucket; a limiter that is still off always grants. */
    switch (s_rate_limiter_acquire(token, strategy->fast_fail_if_no_token)) {
        case ADAPTIVE_GATE_GRANTED:
            /* Granted and debited: proceed. */
            s_fire_gate_callback(token, AWS_OP_SUCCESS);
            break;
        case ADAPTIVE_GATE_DENIED:
            AWS_LOGF_DEBUG(
                AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
                "id=%p: partition_id " PRInSTR " has no token and fast-fail is set; denying send",
                (void *)token->base.retry_strategy,
                AWS_BYTE_CURSOR_PRI(token->strategy_bucket->partition_id_cur));
            aws_raise_error(AWS_IO_RETRY_PERMISSION_DENIED);
            /* Nothing was debited. */
            s_fire_gate_callback(token, AWS_IO_RETRY_PERMISSION_DENIED);
            break;
        case ADAPTIVE_GATE_WAITING:
            /* scheduling_task fires the callback; don't touch token here, it may already be done. */
            break;
    }
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
    /* The caller's timeout_ms limits how long each send may wait for the rate limiter. */
    token->max_wait_time_ns = aws_timestamp_convert(timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
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

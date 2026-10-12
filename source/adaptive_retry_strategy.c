/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/retry_strategy.h>

#include <aws/io/private/rate_limiter.h>

#include <aws/common/clock.h>
#include <aws/common/mutex.h>
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
 *     errors SERVER_ERROR / CLIENT_ERROR (schedule_retry). TRANSIENT errors do not affect the rte limiter
 *
 * The rate limiter is a single-threaded state machine; this wrapper owns a mutex and takes it around every
 * limiter call so capacity is never observed < 0 across threads.
 *
 * The event loop used for deferral comes from the el_group the caller already supplies for the backoff layer
 * (config->standard_options.backoff_retry_options.el_group). No new config and no reach into standard's
 * internals: this mirrors how exponential_backoff_retry_strategy.c defers its own retries.
 */

/* REQUEST_COST: every send costs exactly one token. */
static const double s_adaptive_request_cost = 1.0;

struct adaptive_strategy {
    struct aws_retry_strategy base;
    struct aws_retry_strategy *standard_strategy;
    struct aws_event_loop_group *el_group;
    bool fast_fail_if_no_token;
    struct {
        struct aws_rate_limiter_token_bucket limiter;
        struct aws_mutex lock;
    } synced_data;
};

struct adaptive_retry_token {
    struct aws_retry_token base;
    struct aws_retry_token *standard_token;
    struct aws_event_loop *bound_loop;
    struct aws_task gate_task;

    aws_retry_strategy_on_retry_token_acquired_fn *original_on_acquired;
    aws_retry_strategy_on_retry_ready_fn *original_on_ready;
    void *original_user_data;

    /* Set while a gate task is pending so the deferred task knows which callback to fire. */
    struct {
        struct aws_mutex mutex;
        bool deferring_acquire;
    } thread_data;
};

/* Runs the GetSendToken gate under the limiter lock. Returns the number of ns the caller must wait (0 = now). */
static uint64_t s_rate_limiter_acquire(struct adaptive_strategy *strategy) {
    uint64_t now = 0;
    if (aws_high_res_clock_get_ticks(&now)) {
        /* Clock failed: can't pace, so fail open and let the send through now. */
        return 0;
    }
    aws_mutex_lock(&strategy->synced_data.lock);
    uint64_t wait_ns =
        aws_rate_limiter_token_bucket_acquire(&strategy->synced_data.limiter, s_adaptive_request_cost, now);
    aws_mutex_unlock(&strategy->synced_data.lock);
    return wait_ns;
}

/* Runs _UpdateClientSendingRate under the limiter lock. */
static void s_rate_limiter_update(struct adaptive_strategy *strategy, bool is_throttling_error) {
    uint64_t now = 0;
    if (aws_high_res_clock_get_ticks(&now)) {
        /* Clock failed: skip this update rather than move the rate against a bogus time. */
        return;
    }
    aws_mutex_lock(&strategy->synced_data.lock);
    aws_rate_limiter_token_bucket_update_sending_rate(&strategy->synced_data.limiter, is_throttling_error, now);
    aws_mutex_unlock(&strategy->synced_data.lock);
}

/* Fires the appropriate original callback for a send that is now allowed to proceed. */
static void s_fire_gate_callback(struct adaptive_retry_token *token, bool is_acquire, int error_code) {
    if (is_acquire) {
        if (!error_code) {
            token->original_on_acquired(
                token->base.retry_strategy, error_code, &token->base, token->original_user_data);
        } else {
            token->original_on_acquired(token->base.retry_strategy, error_code, NULL, token->original_user_data);
        }
    } else {
        token->original_on_ready(&token->base, error_code, token->original_user_data);
    }
}

/* The gate task reschedules itself through this on a lost re-acquire race. */
static void s_schedule_gate_task(
    struct adaptive_retry_token *token,
    bool is_acquire,
    uint64_t wait_ns,
    bool reused_ref);

/*
 * Re-acquire at the current time so the token is debited at the real
 * send moment and capacity never commits below zero if other threads drained it during the wait.
 */
static void s_adaptive_gate_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct adaptive_retry_token *token = arg;

    bool is_acquire;
    AWS_FATAL_ASSERT(!aws_mutex_lock(&token->thread_data.mutex) && "mutex lock failed");
    is_acquire = token->thread_data.deferring_acquire;
    token->thread_data.deferring_acquire = false;
    AWS_FATAL_ASSERT(!aws_mutex_unlock(&token->thread_data.mutex) && "mutex unlock failed");

    /* On event loop shutting down deliver cancellation and release refs. */
    if (status != AWS_TASK_STATUS_RUN_READY) {
        s_fire_gate_callback(token, is_acquire, AWS_ERROR_IO_OPERATION_CANCELLED);
        /* Acquire delivered NULL, so the caller can't release the creation ref; drop it here. */
        if (is_acquire) {
            aws_retry_token_release(&token->base);
        }
        /* scheduling ref. */
        aws_retry_token_release(&token->base);
        return;
    }

    struct adaptive_strategy *strategy = token->base.retry_strategy->impl;
    uint64_t wait_ns = s_rate_limiter_acquire(strategy);

    if (wait_ns == 0) {
        /* Granted and debited now: proceed, drop the scheduling ref. */
        s_fire_gate_callback(token, is_acquire, AWS_OP_SUCCESS);
        aws_retry_token_release(&token->base);
        return;
    }

    if (strategy->fast_fail_if_no_token) {
        /* Lost the race during the wait and fast-fail is set. */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: adaptive rate limiter has no token after waiting and fast-fail is set; denying send",
            (void *)token->base.retry_strategy);
        aws_raise_error(AWS_IO_RETRY_PERMISSION_DENIED);
        s_fire_gate_callback(token, is_acquire, AWS_IO_RETRY_PERMISSION_DENIED);
        if (is_acquire) {
            aws_retry_token_release(&token->base);
        }
        aws_retry_token_release(&token->base);
        return;
    }

    /* Reschedule for the new wait, carrying the ref forward. Converges because each wait refills. */
    s_schedule_gate_task(token, is_acquire, wait_ns, true /*reused_ref*/);
}

/*
 * Schedules the gate task wait_ns out. Holds a ref until the task runs; reused_ref=true means the task is
 * rescheduling itself and already holds that ref.
 */
static void s_schedule_gate_task(
    struct adaptive_retry_token *token,
    bool is_acquire,
    uint64_t wait_ns,
    bool reused_ref) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
        "id=%p: adaptive rate limiter pacing send by %" PRIu64 " ns",
        (void *)token->base.retry_strategy,
        wait_ns);

    AWS_FATAL_ASSERT(!aws_mutex_lock(&token->thread_data.mutex) && "mutex lock failed");
    token->thread_data.deferring_acquire = is_acquire;
    AWS_FATAL_ASSERT(!aws_mutex_unlock(&token->thread_data.mutex) && "mutex unlock failed");

    aws_task_init(&token->gate_task, s_adaptive_gate_task, token, "aws_adaptive_retry_gate_task");

    uint64_t current_time = 0;
    if (aws_event_loop_current_clock_time(token->bound_loop, &current_time)) {
        /* Clock failed: fail open (send now) rather than fire at time 0 or strand the token. */
        AWS_LOGF_WARN(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: event loop clock read failed while pacing; failing open and sending now",
            (void *)token->base.retry_strategy);
        s_fire_gate_callback(token, is_acquire, AWS_OP_SUCCESS);
        if (reused_ref) {
            aws_retry_token_release(&token->base);
        }
        return;
    }

    /* Hold the token until the task runs (skip if reusing the prior task's ref). */
    if (!reused_ref) {
        aws_retry_token_acquire(&token->base);
    }
    aws_event_loop_schedule_task_future(token->bound_loop, &token->gate_task, current_time + wait_ns);
}

/*
 * Applies the gate result: grant now, fast-fail, or defer-and-re-acquire after the wait.
 */
static void s_apply_gate(struct adaptive_retry_token *token, bool is_acquire) {
    struct adaptive_strategy *strategy = token->base.retry_strategy->impl;

    uint64_t wait_ns = s_rate_limiter_acquire(strategy);

    if (wait_ns == 0) {
        /* Granted and debited: proceed. */
        s_fire_gate_callback(token, is_acquire, AWS_OP_SUCCESS);
        return;
    }

    if (strategy->fast_fail_if_no_token) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: adaptive rate limiter has no token and fast-fail is set; denying send",
            (void *)token->base.retry_strategy);
        aws_raise_error(AWS_IO_RETRY_PERMISSION_DENIED);
        s_fire_gate_callback(token, is_acquire, AWS_IO_RETRY_PERMISSION_DENIED);
        /* Acquire delivered NULL, so the caller can't release the creation ref; drop it. Nothing was debited. */
        if (is_acquire) {
            aws_retry_token_release(&token->base);
        }
        return;
    }

    /* Defer; the debit happens when the re-acquire grants. */
    s_schedule_gate_task(token, is_acquire, wait_ns, false /*reused_ref*/);
}

static void s_adaptive_retry_destroy(struct aws_retry_strategy *retry_strategy) {
    AWS_LOGF_TRACE(AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY, "id=%p: destroying adaptive strategy", (void *)retry_strategy);
    struct adaptive_strategy *strategy = retry_strategy->impl;
    struct aws_event_loop_group *el_group = strategy->el_group;
    aws_retry_strategy_release(strategy->standard_strategy);
    aws_mutex_clean_up(&strategy->synced_data.lock);
    aws_mem_release(retry_strategy->allocator, strategy);
    aws_event_loop_group_release(el_group);
}

/*
 * Trampoline for the inner standard strategy's token acquisition. Seats the inner token on our wrapper token,
 * then applies the GetSendToken gate (which fires the caller's on_acquired, immediately or deferred).
 */
static void s_on_adaptive_token_acquired(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data) {
    (void)retry_strategy;

    struct adaptive_retry_token *adaptive_token = user_data;

    aws_retry_token_acquire(&adaptive_token->base);
    if (!error_code) {
        adaptive_token->standard_token = token;
        /* GetSendToken gate: fires original_on_acquired (immediately, deferred, or fast-failed). */
        s_apply_gate(adaptive_token, true /*is_acquire*/);
    } else {
        /* Inner acquisition failed; the limiter is not consulted. Propagate the error straight through. */
        adaptive_token->original_on_acquired(
            adaptive_token->base.retry_strategy, error_code, NULL, adaptive_token->original_user_data);
        /* The caller received a NULL token and cannot release it, so drop the creation ref here. */
        aws_retry_token_release(&adaptive_token->base);
    }
    aws_retry_token_release(&adaptive_token->base);
}

static int s_adaptive_retry_acquire_token(
    struct aws_retry_strategy *retry_strategy,
    const struct aws_byte_cursor *partition_id,
    aws_retry_strategy_on_retry_token_acquired_fn *on_acquired,
    void *user_data,
    uint64_t timeout_ms) {

    struct adaptive_strategy *strategy = retry_strategy->impl;

    struct adaptive_retry_token *token =
        aws_mem_calloc(retry_strategy->allocator, 1, sizeof(struct adaptive_retry_token));
    if (!token) {
        return AWS_OP_ERR;
    }

    token->original_user_data = user_data;
    token->original_on_acquired = on_acquired;
    token->base.retry_strategy = retry_strategy;
    token->base.allocator = retry_strategy->allocator;
    token->base.impl = token;
    token->bound_loop = aws_event_loop_group_get_next_loop(strategy->el_group);
    aws_atomic_init_int(&token->base.ref_count, 1u);
    AWS_FATAL_ASSERT(!aws_mutex_init(&token->thread_data.mutex) && "mutex init failed");
    aws_retry_strategy_acquire(retry_strategy);

    if (aws_retry_strategy_acquire_retry_token(
            strategy->standard_strategy, partition_id, s_on_adaptive_token_acquired, token, timeout_ms)) {
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
static void s_on_adaptive_retry_ready(struct aws_retry_token *token, int error_code, void *user_data) {
    (void)token;

    struct aws_retry_token *adaptive_retry_token = user_data;
    struct adaptive_retry_token *impl = adaptive_retry_token->impl;

    if (!error_code) {
        /* GetSendToken gate before the retry: fires original_on_ready (immediately, deferred, or fast-failed). */
        s_apply_gate(impl, false /*is_acquire*/);
    } else {
        /* Inner retry was cancelled/failed; propagate straight through without consulting the limiter. */
        impl->original_on_ready(adaptive_retry_token, error_code, impl->original_user_data);
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
    struct adaptive_strategy *strategy = token->retry_strategy->impl;

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
        s_rate_limiter_update(strategy, true /*is_throttling_error*/);
    } else if (error_type != AWS_RETRY_ERROR_TYPE_TRANSIENT) {
        s_rate_limiter_update(strategy, false /*is_throttling_error*/);
    }

    impl->original_user_data = user_data;
    impl->original_on_ready = retry_ready;

    /* acquire before scheduling to prevent clean up before the callback runs. */
    aws_retry_token_acquire(&impl->base);
    if (aws_retry_strategy_schedule_retry(impl->standard_token, error_type, s_on_adaptive_retry_ready, token)) {
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
    struct adaptive_strategy *strategy = token->retry_strategy->impl;

    /* Bookkeeping: a successful response grows the allowed rate along the CUBIC curve (no-op while disabled). */
    s_rate_limiter_update(strategy, false /*is_throttling_error*/);

    return aws_retry_token_record_success(impl->standard_token);
}

static void s_adaptive_retry_release_token(struct aws_retry_token *token) {
    if (token) {
        AWS_LOGF_TRACE(AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY, "id=%p: releasing adaptive token", (void *)token);
        struct adaptive_retry_token *impl = token->impl;
        aws_retry_token_release(impl->standard_token);
        aws_retry_strategy_release(token->retry_strategy);
        aws_mutex_clean_up(&impl->thread_data.mutex);
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
    if (!strategy) {
        AWS_LOGF_ERROR(AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY, "static: allocation of new adaptive retry strategy failed");
        return NULL;
    }

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

    /* Read the seed time before acquiring the el_group/mutex so the error label below stays correct. */
    uint64_t now = 0;
    if (aws_high_res_clock_get_ticks(&now)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_ADAPTIVE_RETRY_STRATEGY,
            "id=%p: clock read failed while creating adaptive strategy: %s",
            (void *)&strategy->base,
            aws_error_debug_str(aws_last_error()));
        goto error;
    }

    strategy->el_group = aws_event_loop_group_acquire(config->standard_options.backoff_retry_options.el_group);
    strategy->fast_fail_if_no_token = config->fast_fail_if_no_token;
    AWS_FATAL_ASSERT(!aws_mutex_init(&strategy->synced_data.lock) && "mutex init failed");
    aws_rate_limiter_token_bucket_init(&strategy->synced_data.limiter, now);

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

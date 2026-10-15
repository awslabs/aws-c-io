#ifndef AWS_IO_PRIVATE_RATE_LIMITER_H
#define AWS_IO_PRIVATE_RATE_LIMITER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

#include <stdbool.h>
#include <stdint.h>

AWS_PUSH_SANE_WARNING_LEVEL

/**
 * Client-side rate limiter used by the adaptive retry strategy
 *
 * This is a single-threaded state machine: it acquires no locks and never sleeps. It reads the
 * current time itself from aws_high_res_clock_get_ticks, where the SEP calls time(). The caller
 * is responsible for serializing access (the adaptive strategy wraps every call in its own mutex).
 *
 * All rates are expressed in requests-per-second as doubles. The bucket starts DISABLED; the
 * first throttling response seen by aws_rate_limiter_token_bucket_update_sending_rate() flips
 * the one-way enable latch. While disabled, acquire() is a no-op that returns 0 (send now).
 */
struct aws_rate_limiter_token_bucket {
    /* One-way latch. false until the first throttle is observed */
    bool enabled;
    /* last_timestamp. */
    bool last_timestamp_set;

    /* Tokens per second. */
    double fill_rate;
    /* Ceiling of the bucket. */
    double max_capacity;
    /* Tokens available now. */
    double current_capacity;

    /* Exponentially smoothed estimate of the rate the client is actually achieving. */
    double measured_tx_rate;
    /* Half-second-aligned bucket boundary (in seconds) for the measured-rate estimator. */
    double last_tx_rate_bucket;
    /* Requests counted in the current measurement bucket. */
    uint64_t request_count;

    /* Allowed rate captured at the last throttle; the CUBIC curve's y-origin. */
    double last_max_rate;
    /* Time (seconds) of the last throttle; the CUBIC curve's x-origin. */
    double last_throttle_time;

    /* Last refill time, nanoseconds. Valid only when last_timestamp_set is true. */
    uint64_t last_timestamp_ns;
};

AWS_EXTERN_C_BEGIN

/**
 * Initializes the bucket into the disabled state. The current time seeds the measured-rate bucket origin.
 */
AWS_IO_API void aws_rate_limiter_token_bucket_init(struct aws_rate_limiter_token_bucket *limiter);

/**
 * Resets the bucket back to its freshly-initialized (disabled) state.
 */
AWS_IO_API void aws_rate_limiter_token_bucket_reset(struct aws_rate_limiter_token_bucket *limiter);

/**
 * GetSendToken gate. Attempts to take `amount` tokens.
 *
 * Does NOT sleep. Returns the number of nanoseconds the caller must wait before the tokens are
 * available (0 means "send now"). The caller either defers the send on an event loop by the
 * returned amount, or fast-fails, per the strategy's configuration.
 *
 * While the bucket is disabled this always returns 0 and takes nothing. In the real algorithm
 * `amount` is always REQUEST_COST (1); the parameter exists for genericity and testability.
 */
AWS_IO_API uint64_t aws_rate_limiter_token_bucket_acquire(struct aws_rate_limiter_token_bucket *limiter, double amount);

/**
 * RequestBookkeeping -> _UpdateClientSendingRate. Feeds the controller one
 * response signal: is_throttling_error true cuts the allowed rate (CUBIC down + enable latch);
 * false grows it along the cubic curve. Transient-error handling (whether to call this at all
 * for a transient) is the caller's policy, decided in the adaptive strategy.
 */
AWS_IO_API void aws_rate_limiter_token_bucket_update_sending_rate(
    struct aws_rate_limiter_token_bucket *limiter,
    bool is_throttling_error);

/*
 * Pure CUBIC primitives, exposed so unit tests can hit the CUBIC vectors
 * directly without driving the whole bucket. They operate on the limiter's last_max_rate /
 * last_throttle_time state.
 */

/**
 * _CalculateTimeWindow : cbrt((last_max_rate * (1 - BETA)) / SCALE_CONSTANT).
 */
AWS_IO_API double aws_rate_limiter_cubic_calculate_time_window(double last_max_rate);

/**
 * _CUBICSuccess: SCALE_CONSTANT * (dt - time_window)^3 + last_max_rate, where
 * dt = now_seconds - last_throttle_time. Grows the rate after a success.
 */
AWS_IO_API double aws_rate_limiter_cubic_success(
    double last_max_rate,
    double last_throttle_time,
    double time_window,
    double now_seconds);

/**
 * _CUBICThrottle: rate_to_use * BETA. Cuts the rate on a throttle.
 */
AWS_IO_API double aws_rate_limiter_cubic_throttle(double rate_to_use);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_IO_PRIVATE_RATE_LIMITER_H */

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/private/rate_limiter.h>

#include <aws/common/clock.h>
#include <aws/common/math.h>

#include <math.h>

/*
 * Client-side rate limiter for the adaptive retry strategy.
 * Single-threaded: reads the high-res clock where the SEP calls time(); the caller serializes access.
 */

/* constants. */
#define AWS_RATE_LIMITER_BETA 0.7           /* throttle scale-down: keep 70% */
#define AWS_RATE_LIMITER_SCALE_CONSTANT 0.4 /* CUBIC climb aggressiveness */
#define AWS_RATE_LIMITER_SMOOTH 0.8         /* measured-rate smoothing weight */
#define AWS_RATE_LIMITER_MIN_FILL_RATE 0.5  /* floor on fill_rate */
#define AWS_RATE_LIMITER_MIN_CAPACITY 1.0   /* floor on max_capacity */

/* Converts a nanosecond timestamp to seconds with sub-second resolution. */
static double s_ns_to_seconds(uint64_t now_ns) {
    return (double)now_ns / (double)AWS_TIMESTAMP_NANOS;
}

void aws_rate_limiter_token_bucket_init(struct aws_rate_limiter_token_bucket *limiter) {
    uint64_t now_ns = 0;
    AWS_ZERO_STRUCT(*limiter);
    if (aws_high_res_clock_get_ticks(&now_ns)) {
        return;
    }


    limiter->enabled = false;
    limiter->last_timestamp_set = false;
    limiter->last_tx_rate_bucket = floor(s_ns_to_seconds(now_ns));
    limiter->last_throttle_time = s_ns_to_seconds(now_ns);
}

void aws_rate_limiter_token_bucket_reset(struct aws_rate_limiter_token_bucket *limiter) {
    aws_rate_limiter_token_bucket_init(limiter);
}

/* _TokenBucketRefill: credit tokens accrued since the last refill. */
static void s_token_bucket_refill(struct aws_rate_limiter_token_bucket *limiter) {
    /* timestamp = time() */
    uint64_t now_ns = 0;
      if (aws_high_res_clock_get_ticks(&now_ns)) {
        return;
    }

    if (!limiter->last_timestamp_set) {
        /* First refill just seats the timestamp. */
        limiter->last_timestamp_ns = now_ns;
        limiter->last_timestamp_set = true;
        return;
    }

    double elapsed_seconds = s_ns_to_seconds(now_ns) - s_ns_to_seconds(limiter->last_timestamp_ns);
    double fill_amount = elapsed_seconds * limiter->fill_rate;
    limiter->current_capacity = aws_min_double(limiter->max_capacity, limiter->current_capacity + fill_amount);
    limiter->last_timestamp_ns = now_ns;
}

/* _TokenBucketUpdateRate: refill at the OLD rate, then set the new rate. */
static void s_token_bucket_update_rate(struct aws_rate_limiter_token_bucket *limiter, double new_rps) {

    s_token_bucket_refill(limiter);
    limiter->fill_rate = aws_max_double(new_rps, AWS_RATE_LIMITER_MIN_FILL_RATE);
    limiter->max_capacity = aws_max_double(new_rps, AWS_RATE_LIMITER_MIN_CAPACITY);
    /* Clamp down on scale-down so we never hold more than the new ceiling. */
    limiter->current_capacity = aws_min_double(limiter->current_capacity, limiter->max_capacity);
}

/* _UpdateMeasuredRate: exponentially smoothed rate in half-second buckets. */
static void s_update_measured_rate(struct aws_rate_limiter_token_bucket *limiter, uint64_t now_ns) {
    double t = s_ns_to_seconds(now_ns);
    double time_bucket = floor(t * 2.0) / 2.0;
    limiter->request_count += 1;

    if (time_bucket > limiter->last_tx_rate_bucket) {
        double current_rate = (double)limiter->request_count / (time_bucket - limiter->last_tx_rate_bucket);
        limiter->measured_tx_rate =
            current_rate * AWS_RATE_LIMITER_SMOOTH + limiter->measured_tx_rate * (1.0 - AWS_RATE_LIMITER_SMOOTH);
        limiter->request_count = 0;
        limiter->last_tx_rate_bucket = time_bucket;
    }
}

double aws_rate_limiter_cubic_calculate_time_window(double last_max_rate) {
    /* cbrt((last_max_rate * (1 - BETA)) / SCALE_CONSTANT). */
    return cbrt((last_max_rate * (1.0 - AWS_RATE_LIMITER_BETA)) / AWS_RATE_LIMITER_SCALE_CONSTANT);
}

double aws_rate_limiter_cubic_success(
    double last_max_rate,
    double last_throttle_time,
    double time_window,
    double now_seconds) {

    double dt = now_seconds - last_throttle_time;
    double delta = dt - time_window;
    return AWS_RATE_LIMITER_SCALE_CONSTANT * (delta * delta * delta) + last_max_rate;
}

double aws_rate_limiter_cubic_throttle(double rate_to_use) {
    return rate_to_use * AWS_RATE_LIMITER_BETA;
}

uint64_t aws_rate_limiter_token_bucket_acquire(struct aws_rate_limiter_token_bucket *limiter, double amount) {

    /* No-op until the first throttle enables the limiter. */
    if (!limiter->enabled) {
        return 0;
    }

    s_token_bucket_refill(limiter);

    if (amount <= limiter->current_capacity) {
        /* Capacity available: grant and deduct. */
        limiter->current_capacity -= amount;
        return 0;
    }

    /* A token is only spent on a send that proceeds, so the caller re-acquires after the wait and the debit happens
     * then. */
    double wait_seconds = (amount - limiter->current_capacity) / limiter->fill_rate;
    uint64_t wait_ns = (uint64_t)(wait_seconds * (double)AWS_TIMESTAMP_NANOS);

    /* Rounding can truncate a sub-ns wait to 0, which would read as "granted" without a deduct; floor to 1ns. */
    if (wait_ns == 0) {
        wait_ns = 1;
    }

    return wait_ns;
}

void aws_rate_limiter_token_bucket_update_sending_rate(
    struct aws_rate_limiter_token_bucket *limiter,
    bool is_throttling_error) {

    /* t = time(), shared by the measured-rate and CUBIC math below. */
    uint64_t now_ns = 0;
    if(aws_high_res_clock_get_ticks(&now_ns)){
        return;
    }

    s_update_measured_rate(limiter, now_ns);

    double calculated_rate;
    if (is_throttling_error) {
        double rate_to_use;
        if (!limiter->enabled) {
            rate_to_use = limiter->measured_tx_rate;
        } else {
            rate_to_use = aws_min_double(limiter->measured_tx_rate, limiter->fill_rate);
        }
        limiter->last_max_rate = rate_to_use;
        limiter->last_throttle_time = s_ns_to_seconds(now_ns);
        calculated_rate = aws_rate_limiter_cubic_throttle(rate_to_use);
        /* Enable latch flips on the first throttle. */
        limiter->enabled = true;
    } else {
        double time_window = aws_rate_limiter_cubic_calculate_time_window(limiter->last_max_rate);
        calculated_rate = aws_rate_limiter_cubic_success(
            limiter->last_max_rate, limiter->last_throttle_time, time_window, s_ns_to_seconds(now_ns));
    }

    /* 2x measured-rate burst cap so the ceiling never outruns achievable throughput. */
    double new_rate = aws_min_double(calculated_rate, 2.0 * limiter->measured_tx_rate);
    s_token_bucket_update_rate(limiter, new_rate);
}

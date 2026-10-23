/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/private/rate_limiter.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>

#include <math.h>

/* constants, duplicated here so the tests pin the expected numbers independently of the source. */
#define TEST_BETA 0.7
#define TEST_SCALE_CONSTANT 0.4

/* Converts seconds to nanoseconds. */
static uint64_t s_seconds_to_ns(double seconds) {
    return (uint64_t)(seconds * (double)AWS_TIMESTAMP_NANOS);
}

/* Enables the limiter with a throttle, then sets a known rate and an empty bucket. */
static void s_enable_with_rate(struct aws_rate_limiter_token_bucket *limiter, double fill_rate, double max_capacity) {
    aws_rate_limiter_token_bucket_init(limiter);
    aws_rate_limiter_token_bucket_update_sending_rate(limiter, true /*is_throttling_error*/);
    limiter->fill_rate = fill_rate;
    limiter->max_capacity = max_capacity;
    limiter->current_capacity = 0.0;
}

/* Simulates `seconds` passing by moving the last refill time back. */
static void s_rewind_last_refill(struct aws_rate_limiter_token_bucket *limiter, double seconds) {
    limiter->last_timestamp_ns -= s_seconds_to_ns(seconds);
}

/* A fresh limiter is disabled: acquire returns 0 and takes nothing. */
static int s_test_rate_limiter_starts_disabled(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter);

    ASSERT_FALSE(limiter.enabled);
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1.0));
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1000.0));
    ASSERT_TRUE(limiter.current_capacity == 0.0);
    ASSERT_FALSE(limiter.enabled);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_starts_disabled, s_test_rate_limiter_starts_disabled)

/* Successes leave the limiter off; the first throttle turns it on with floored rate and capacity. */
static int s_test_rate_limiter_first_throttle_enables(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter);

    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, false /*is_throttling_error*/);
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, false /*is_throttling_error*/);
    ASSERT_FALSE(limiter.enabled);

    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, true /*is_throttling_error*/);
    ASSERT_TRUE(limiter.enabled);
    ASSERT_TRUE(limiter.fill_rate >= 0.5);
    ASSERT_TRUE(limiter.max_capacity >= 1.0);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_first_throttle_enables, s_test_rate_limiter_first_throttle_enables)

/* With an empty bucket every acquire reports a wait and never takes tokens. */
static int s_test_rate_limiter_denied_acquire_no_debit(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    s_enable_with_rate(&limiter, 2.0, 10.0);

    for (int i = 0; i < 20; ++i) {
        double before = limiter.current_capacity;
        ASSERT_TRUE(aws_rate_limiter_token_bucket_acquire(&limiter, 1.0) > 0);
        ASSERT_TRUE(limiter.current_capacity >= before);
    }

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_denied_acquire_no_debit, s_test_rate_limiter_denied_acquire_no_debit)

/* An empty bucket filling at 2 tokens/s needs about 0.5s for one token. */
static int s_test_rate_limiter_wait_matches_fill_rate(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    s_enable_with_rate(&limiter, 2.0, 10.0);

    uint64_t wait_ns = aws_rate_limiter_token_bucket_acquire(&limiter, 1.0);
    ASSERT_TRUE(wait_ns <= s_seconds_to_ns(0.5));
    ASSERT_TRUE(wait_ns > s_seconds_to_ns(0.4));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_wait_matches_fill_rate, s_test_rate_limiter_wait_matches_fill_rate)

/* Refill after a long gap stops at max_capacity, and a grant takes exactly one token. */
static int s_test_rate_limiter_refill_caps_at_max(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    s_enable_with_rate(&limiter, 2.0, 3.0);

    s_rewind_last_refill(&limiter, 10.0);
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1.0));
    ASSERT_TRUE(limiter.current_capacity == 2.0);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_refill_caps_at_max, s_test_rate_limiter_refill_caps_at_max)

/* A full bucket grants one send per token, then the next send has to wait. */
static int s_test_rate_limiter_grants_until_empty(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    s_enable_with_rate(&limiter, 2.0, 3.0);
    limiter.current_capacity = 3.0;

    for (int i = 0; i < 3; ++i) {
        ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1.0));
    }
    ASSERT_TRUE(aws_rate_limiter_token_bucket_acquire(&limiter, 1.0) > 0);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_grants_until_empty, s_test_rate_limiter_grants_until_empty)

/* 10s after a throttle, a success climbs the CUBIC curve above the throttled rate. */
static int s_test_rate_limiter_success_grows_rate(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    s_enable_with_rate(&limiter, 7.0, 7.0);
    limiter.last_max_rate = 10.0;
    /* Keep the cached time window in sync with the directly-set last_max_rate. */
    limiter.time_window = aws_rate_limiter_cubic_calculate_time_window(limiter.last_max_rate);
    limiter.measured_tx_rate = 100.0;
    limiter.last_throttle_time -= 10.0;

    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, false /*is_throttling_error*/);
    ASSERT_TRUE(limiter.fill_rate > 7.0);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_success_grows_rate, s_test_rate_limiter_success_grows_rate)

/* reset returns an enabled limiter to the disabled state. */
static int s_test_rate_limiter_reset_disables(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    s_enable_with_rate(&limiter, 2.0, 10.0);
    ASSERT_TRUE(limiter.enabled);

    aws_rate_limiter_token_bucket_reset(&limiter);
    ASSERT_FALSE(limiter.enabled);
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1000.0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_reset_disables, s_test_rate_limiter_reset_disables)

/* _CUBICThrottle is an exact BETA scale-down of the input rate. */
static int s_test_rate_limiter_cubic_throttle_vector(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    double out = aws_rate_limiter_cubic_throttle(10.0);
    ASSERT_TRUE(fabs(out - (10.0 * TEST_BETA)) < 1e-9);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_cubic_throttle_vector, s_test_rate_limiter_cubic_throttle_vector)

/* _CalculateTimeWindow is the documented cube root of (last_max_rate * (1 - BETA)) / SCALE_CONSTANT. */
static int s_test_rate_limiter_cubic_time_window_vector(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    double last_max_rate = 10.0;
    double expected = cbrt((last_max_rate * (1.0 - TEST_BETA)) / TEST_SCALE_CONSTANT);
    double out = aws_rate_limiter_cubic_calculate_time_window(last_max_rate);
    ASSERT_TRUE(fabs(out - expected) < 1e-9);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_cubic_time_window_vector, s_test_rate_limiter_cubic_time_window_vector)

/* _CUBICSuccess at exactly the time window returns the last_max_rate (the curve's inflection). */
static int s_test_rate_limiter_cubic_success_vector(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    double last_max_rate = 10.0;
    double last_throttle_time = 5.0;
    double time_window = aws_rate_limiter_cubic_calculate_time_window(last_max_rate);
    /* At now = throttle_time + time_window, dt - time_window == 0, so the cube term vanishes. */
    double now_seconds = last_throttle_time + time_window;
    double out = aws_rate_limiter_cubic_success(last_max_rate, last_throttle_time, time_window, now_seconds);
    ASSERT_TRUE(fabs(out - last_max_rate) < 1e-9);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_cubic_success_vector, s_test_rate_limiter_cubic_success_vector)

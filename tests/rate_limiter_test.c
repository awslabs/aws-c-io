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

/* Converts whole seconds to a nanosecond timestamp for the time arguments. */
static uint64_t s_seconds_to_ns(double seconds) {
    return (uint64_t)(seconds * (double)AWS_TIMESTAMP_NANOS);
}

/* A freshly initialized bucket is disabled and acquire is a no-op returning 0. */
static int s_test_rate_limiter_starts_disabled(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter, 0);

    ASSERT_FALSE(limiter.enabled);
    /* Many acquires while disabled all return 0 and never move capacity. */
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1.0, s_seconds_to_ns(1.0)));
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1000.0, s_seconds_to_ns(2.0)));
    ASSERT_FALSE(limiter.enabled);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_starts_disabled, s_test_rate_limiter_starts_disabled)

/* The first throttling response flips the one-way enable latch and cuts the rate to BETA of measured. */
static int s_test_rate_limiter_first_throttle_enables_and_cuts(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter, 0);

    /* Prime the measured rate with a few successes inside one measurement window. */
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, false, s_seconds_to_ns(0.0));
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, false, s_seconds_to_ns(0.1));
    ASSERT_FALSE(limiter.enabled);

    /* First throttle: enable latch flips, rate becomes BETA * measured. */
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, true, s_seconds_to_ns(1.0));
    ASSERT_TRUE(limiter.enabled);
    ASSERT_TRUE(limiter.fill_rate >= 0.5);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_first_throttle_enables_and_cuts, s_test_rate_limiter_first_throttle_enables_and_cuts)

/* Once enabled, an over-budget acquire returns a positive wait and does NOT deduct; a fitting one grants. */
static int s_test_rate_limiter_enabled_acquire_paces(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter, 0);

    /* Enable via a throttle. */
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, true, s_seconds_to_ns(1.0));
    ASSERT_TRUE(limiter.enabled);

    /* An over-budget acquire reports a wait and leaves capacity untouched (debit only happens on a grant). */
    double before = limiter.current_capacity;
    double big = limiter.max_capacity + 100.0;
    uint64_t wait_ns = aws_rate_limiter_token_bucket_acquire(&limiter, big, s_seconds_to_ns(1.0));
    ASSERT_TRUE(wait_ns > 0);
    ASSERT_TRUE(limiter.current_capacity == before);
    ASSERT_FALSE(limiter.current_capacity < 0.0);

    /*
     * After a throttle current_capacity starts at 0, so a grant needs refill. At fill_rate 0.5/s, 4 seconds
     * accrues ~2.0 (capped at max_capacity 1.0). A unit acquire then grants immediately (wait 0) and debits.
     */
    uint64_t grant_wait = aws_rate_limiter_token_bucket_acquire(&limiter, 1.0, s_seconds_to_ns(5.0));
    ASSERT_UINT_EQUALS(0, grant_wait);
    ASSERT_TRUE(limiter.current_capacity == 0.0);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_enabled_acquire_paces, s_test_rate_limiter_enabled_acquire_paces)

/* Capacity accrues over time at fill_rate: waiting long enough makes a later acquire free. */
static int s_test_rate_limiter_refills_over_time(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter, 0);
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, true, s_seconds_to_ns(1.0));

    /* Spend what capacity exists (a grant debits down toward zero, never below). */
    aws_rate_limiter_token_bucket_acquire(&limiter, limiter.max_capacity, s_seconds_to_ns(1.0));

    /* After a generous interval the bucket refills and a unit acquire is free again. */
    uint64_t wait_ns = aws_rate_limiter_token_bucket_acquire(&limiter, 1.0, s_seconds_to_ns(100.0));
    ASSERT_UINT_EQUALS(0, wait_ns);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_refills_over_time, s_test_rate_limiter_refills_over_time)

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

/* reset returns an enabled bucket to the freshly-initialized disabled state. */
static int s_test_rate_limiter_reset_disables(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter, 0);
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, true, s_seconds_to_ns(1.0));
    ASSERT_TRUE(limiter.enabled);

    aws_rate_limiter_token_bucket_reset(&limiter, s_seconds_to_ns(2.0));
    ASSERT_FALSE(limiter.enabled);
    ASSERT_UINT_EQUALS(0, aws_rate_limiter_token_bucket_acquire(&limiter, 1000.0, s_seconds_to_ns(3.0)));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_reset_disables, s_test_rate_limiter_reset_disables)

/* A denied (wait-returning) acquire never debits, so repeated denials cannot drive capacity below zero. */
static int s_test_rate_limiter_denied_acquire_no_debit(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_rate_limiter_token_bucket limiter;
    aws_rate_limiter_token_bucket_init(&limiter, 0);
    aws_rate_limiter_token_bucket_update_sending_rate(&limiter, true, s_seconds_to_ns(1.0));
    ASSERT_TRUE(limiter.enabled);

    /* Spend the available capacity with a grant so the next requests must wait. */
    aws_rate_limiter_token_bucket_acquire(&limiter, limiter.current_capacity, s_seconds_to_ns(1.0));

    /* Many over-budget acquires at the same instant each report a wait and leave capacity put. */
    double big = limiter.max_capacity + 50.0;
    for (int i = 0; i < 20; ++i) {
        double before = limiter.current_capacity;
        uint64_t wait_ns = aws_rate_limiter_token_bucket_acquire(&limiter, big, s_seconds_to_ns(1.0));
        ASSERT_TRUE(wait_ns > 0);
        ASSERT_TRUE(limiter.current_capacity == before);
        ASSERT_FALSE(limiter.current_capacity < 0.0);
    }

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_rate_limiter_denied_acquire_no_debit, s_test_rate_limiter_denied_acquire_no_debit)

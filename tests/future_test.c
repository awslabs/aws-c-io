/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/future.h>

#include <aws/common/clock.h>
#include <aws/common/ref_count.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>
#include <aws/io/channel.h>
#include <aws/io/event_loop.h>
#include <aws/testing/aws_test_harness.h>

#include "future_test.h"

#define ONE_SEC_IN_NS ((uint64_t)AWS_TIMESTAMP_NANOS)
#define MAX_TIMEOUT_NS (10 * ONE_SEC_IN_NS)

AWS_FUTURE_T_POINTER_WITH_DESTROY_IMPLEMENTATION(aws_future_destroyme, struct aws_destroyme, aws_destroyme_destroy);
AWS_FUTURE_T_POINTER_WITH_RELEASE_IMPLEMENTATION(aws_future_refcountme, struct aws_refcountme, aws_refcountme_release);

/* Run through the basics of an AWS_FUTURE_T_BY_VALUE */
static int s_test_future_by_value(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_bool *future = aws_future_bool_new(alloc);
    ASSERT_NOT_NULL(future);

    ASSERT_FALSE(aws_future_bool_is_done(future));

    /* set result */
    aws_future_bool_set_result(future, true);
    ASSERT_TRUE(aws_future_bool_is_done(future));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(future));
    ASSERT_TRUE(aws_future_bool_get_result(future));

    future = aws_future_bool_release(future);
    ASSERT_NULL(future);

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_by_value, s_test_future_by_value)

/* Run through the basics of an aws_future<void> */
static int s_test_future_void(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_void *future = aws_future_void_new(alloc);
    ASSERT_NOT_NULL(future);

    ASSERT_FALSE(aws_future_void_is_done(future));

    /* set valueless result */
    aws_future_void_set_result(future);
    ASSERT_TRUE(aws_future_void_is_done(future));
    ASSERT_INT_EQUALS(0, aws_future_void_get_error(future));

    future = aws_future_void_release(future);
    ASSERT_NULL(future);

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_void, s_test_future_void)

struct future_size_callback_recorder {
    struct aws_future_size *future;    /* record all state when this future's callback fires */
    struct aws_event_loop *event_loop; /* record whether callback fires on this event-loop's thread */
    struct aws_channel *channel;

    /* record state of the world when callback invoked */
    int error_code;
    size_t result;
    aws_thread_id_t thread_id;
    bool is_event_loop_thread;
    int invoke_count;
};

static void s_record_on_future_size_done(void *user_data) {
    struct future_size_callback_recorder *recorder = user_data;
    recorder->error_code = aws_future_size_get_error(recorder->future);
    if (recorder->error_code == 0) {
        recorder->result = aws_future_size_get_result(recorder->future);
    }
    recorder->thread_id = aws_thread_current_thread_id();
    recorder->invoke_count++;

    if (recorder->event_loop) {
        recorder->is_event_loop_thread = aws_event_loop_thread_is_callers_thread(recorder->event_loop);
    }
}

/* Test callback firing immediately upon registration */
static int s_test_future_callback_fires_immediately(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct future_size_callback_recorder recorder;
    AWS_ZERO_STRUCT(recorder);

    recorder.future = aws_future_size_new(alloc);
    aws_future_size_set_result(recorder.future, 123);

    aws_future_size_register_callback(recorder.future, s_record_on_future_size_done, &recorder);

    /* callback should have fired immediately, on main thread, since future was already done */
    ASSERT_INT_EQUALS(1, recorder.invoke_count);
    ASSERT_INT_EQUALS(0, recorder.error_code);
    ASSERT_UINT_EQUALS(123, recorder.result);

    aws_thread_id_t main_thread_id = aws_thread_current_thread_id();
    ASSERT_INT_EQUALS(0, memcmp(&main_thread_id, &recorder.thread_id, sizeof(aws_thread_id_t)));

    aws_future_size_release(recorder.future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_callback_fires_immediately, s_test_future_callback_fires_immediately);

struct future_size_thread_job {
    struct aws_allocator *alloc;
    uint64_t delay_ns;
    struct aws_future_size *my_future;
};

/* Function that runs on thread, and completes future after delay */
static void s_run_thread_job(void *user_data) {
    struct future_size_thread_job *job = user_data;

    aws_thread_current_sleep(job->delay_ns);
    aws_future_size_set_result(job->my_future, 987);

    aws_future_size_release(job->my_future);
    aws_mem_release(job->alloc, job);
}

/* Start thread that will complete future after delay */
static struct aws_future_size *s_start_thread_job(struct aws_allocator *alloc, uint64_t delay_ns) {
    struct aws_future_size *future = aws_future_size_new(alloc);

    struct future_size_thread_job *job = aws_mem_calloc(alloc, 1, sizeof(struct future_size_thread_job));
    job->alloc = alloc;
    job->delay_ns = delay_ns;
    job->my_future = aws_future_size_acquire(future);

    struct aws_thread thread;
    AWS_FATAL_ASSERT(aws_thread_init(&thread, alloc) == AWS_OP_SUCCESS);

    struct aws_thread_options thread_options = *aws_default_thread_options();
    thread_options.join_strategy = AWS_TJS_MANAGED;
    thread_options.name = aws_byte_cursor_from_c_str("FutureSizeJob");

    AWS_FATAL_ASSERT(aws_thread_launch(&thread, s_run_thread_job, job, &thread_options) == AWS_OP_SUCCESS);

    return future;
}

/* Test callback firing on a different thread than the one that registered it.
 * This is the first test that looks like real-world use of aws_future */
static int s_test_future_callback_fires_on_another_thread(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    /* Kick off thread, which will set result in 1sec */
    struct future_size_callback_recorder recorder = {
        .future = s_start_thread_job(alloc, ONE_SEC_IN_NS /*delay_ns*/),
    };

    aws_future_size_register_callback(recorder.future, s_record_on_future_size_done, &recorder);

    /* Wait until other thread joins, at which point the future is complete and the callback has fired */
    aws_thread_set_managed_join_timeout_ns(MAX_TIMEOUT_NS);
    ASSERT_SUCCESS(aws_thread_join_all_managed());

    /* callback should have fired on the other thread */
    ASSERT_INT_EQUALS(1, recorder.invoke_count);
    ASSERT_INT_EQUALS(0, recorder.error_code);
    ASSERT_UINT_EQUALS(987, recorder.result);

    aws_thread_id_t main_thread_id = aws_thread_current_thread_id();
    ASSERT_TRUE(memcmp(&main_thread_id, &recorder.thread_id, sizeof(aws_thread_id_t)) != 0);

    aws_future_size_release(recorder.future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_callback_fires_on_another_thread, s_test_future_callback_fires_on_another_thread);

static int s_test_future_register_callback_if_not_done(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    {
        /* the callback should not get registered if future is already done */
        struct future_size_callback_recorder recorder = {
            .future = aws_future_size_new(alloc),
        };
        aws_future_size_set_result(recorder.future, 555);
        ASSERT_FALSE(
            aws_future_size_register_callback_if_not_done(recorder.future, s_record_on_future_size_done, &recorder));

        ASSERT_INT_EQUALS(0, recorder.invoke_count);
        aws_future_size_release(recorder.future);
    }

    {
        /* the callback should get registered if the future isn't done yet */
        struct future_size_callback_recorder recorder = {
            .future = aws_future_size_new(alloc),
        };
        ASSERT_TRUE(
            aws_future_size_register_callback_if_not_done(recorder.future, s_record_on_future_size_done, &recorder));
        ASSERT_INT_EQUALS(0, recorder.invoke_count);

        /* now set result, the callback should fire */
        aws_future_size_set_result(recorder.future, 555);
        ASSERT_INT_EQUALS(1, recorder.invoke_count);

        /* after callback fires, you're allowed to call register_callback_if_not_done() again.
         * (This makes it easy to call an async function repeatedly in a loop,
         * where you keep looping as long as the futures complete immediately,
         * but bail out if the callback gets registered) */
        ASSERT_FALSE(
            aws_future_size_register_callback_if_not_done(recorder.future, s_record_on_future_size_done, &recorder));

        /* make sure callback didn't fire a 2nd time */
        ASSERT_INT_EQUALS(1, recorder.invoke_count);

        aws_future_size_release(recorder.future);
    }
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_register_callback_if_not_done, s_test_future_register_callback_if_not_done)

/* Test that an event-loop callback still runs if it's registered after the future is already done */
static int s_test_future_register_event_loop_callback_after_done(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct future_size_callback_recorder recorder = {
        .future = aws_future_size_new(alloc),
        .event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks),
    };
    ASSERT_SUCCESS(aws_event_loop_run(recorder.event_loop));

    /* register callback after result already set */
    aws_future_size_set_result(recorder.future, 765);

    aws_future_size_register_event_loop_callback(
        recorder.future, recorder.event_loop, s_record_on_future_size_done, &recorder);

    /* Wait until event loop is destroyed, at which point the future is complete and the callback has fired */
    aws_event_loop_destroy(recorder.event_loop);

    /* callback should have fired on event-loop thread */
    ASSERT_INT_EQUALS(1, recorder.invoke_count);
    ASSERT_INT_EQUALS(0, recorder.error_code);
    ASSERT_UINT_EQUALS(765, recorder.result);
    ASSERT_TRUE(recorder.is_event_loop_thread);

    /* cleanup */
    aws_future_size_release(recorder.future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_register_event_loop_callback_after_done, s_test_future_register_event_loop_callback_after_done)

/* Test that an event-loop callback still runs if it's registered before the future is done */
static int s_test_future_register_event_loop_callback_before_done(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct future_size_callback_recorder recorder = {
        .future = aws_future_size_new(alloc),
        .event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks),
    };
    ASSERT_SUCCESS(aws_event_loop_run(recorder.event_loop));

    /* register callback before result is set */
    aws_future_size_register_event_loop_callback(
        recorder.future, recorder.event_loop, s_record_on_future_size_done, &recorder);

    aws_future_size_set_result(recorder.future, 765);

    /* Wait until event loop is destroyed, at which point the future is complete and the callback has fired */
    aws_event_loop_destroy(recorder.event_loop);

    /* callback should have fired on event-loop thread */
    ASSERT_INT_EQUALS(1, recorder.invoke_count);
    ASSERT_INT_EQUALS(0, recorder.error_code);
    ASSERT_UINT_EQUALS(765, recorder.result);
    ASSERT_TRUE(recorder.is_event_loop_thread);

    /* cleanup */
    aws_future_size_release(recorder.future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_register_event_loop_callback_before_done, s_test_future_register_event_loop_callback_before_done)

void s_set_result_from_event_loop_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct future_size_callback_recorder *recorder = user_data;

    AWS_FATAL_ASSERT(recorder->invoke_count == 0); /* The future shouldn't be done yet */

    aws_future_size_set_result(recorder->future, 1234567);

    /* The callback should NOT be invoked from the same callstack as set_result().
     * The callback should run as its own scheduled task */
    AWS_FATAL_ASSERT(recorder->invoke_count == 0);
}

/* Test that an event-loop callback always runs as its own scheduled task.
 * Even if set_result() is called from the event-loop thread, the callback
 * should NOT run in the same callstack as set_result() */
static int s_test_future_register_event_loop_callback_always_scheduled(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct future_size_callback_recorder recorder = {
        .future = aws_future_size_new(alloc),
        .event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks),
    };
    ASSERT_SUCCESS(aws_event_loop_run(recorder.event_loop));

    /* register callback before result is set */
    aws_future_size_register_event_loop_callback(
        recorder.future, recorder.event_loop, s_record_on_future_size_done, &recorder);

    struct aws_task set_result_from_event_loop_task;
    aws_task_init(
        &set_result_from_event_loop_task, s_set_result_from_event_loop_task, &recorder, "set_result_from_event_loop");

    aws_event_loop_schedule_task_now(recorder.event_loop, &set_result_from_event_loop_task);

    /* Wait until event loop is destroyed, at which point the future is complete and the callback has fired */
    aws_event_loop_destroy(recorder.event_loop);

    /* callback should have fired on event-loop thread */
    ASSERT_INT_EQUALS(1, recorder.invoke_count);
    ASSERT_INT_EQUALS(0, recorder.error_code);
    ASSERT_UINT_EQUALS(1234567, recorder.result);
    ASSERT_TRUE(recorder.is_event_loop_thread);

    /* cleanup */
    aws_future_size_release(recorder.future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(
    future_register_event_loop_callback_always_scheduled,
    s_test_future_register_event_loop_callback_always_scheduled)

static void s_on_channel_setup(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct aws_future_void *setup_future = user_data;
    if (error_code) {
        aws_future_void_set_error(setup_future, error_code);
    } else {
        aws_future_void_set_result(setup_future);
    }
}

/* Test channel callback */
static int s_test_future_register_channel_callback(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    /* Set up event-loop */
    struct future_size_callback_recorder recorder = {
        .future = aws_future_size_new(alloc),
        .event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks),
    };
    ASSERT_SUCCESS(aws_event_loop_run(recorder.event_loop));

    /* Set up channel */
    struct aws_future_void *channel_setup_future = aws_future_void_new(alloc);
    struct aws_channel_options channel_options = {
        .event_loop = recorder.event_loop,
        .on_setup_completed = s_on_channel_setup,
        .setup_user_data = channel_setup_future,
    };
    struct aws_channel *channel = aws_channel_new(alloc, &channel_options);
    ASSERT_TRUE(aws_future_void_wait(channel_setup_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_void_get_error(channel_setup_future));

    /* register callback after result already set */
    aws_future_size_set_result(recorder.future, 234567);

    aws_future_size_register_channel_callback(recorder.future, channel, s_record_on_future_size_done, &recorder);

    /* wait until channel/event-loop are destroyed,
     * at which point the future is complete and the callback has fired */
    aws_channel_release_hold(channel);
    aws_event_loop_destroy(recorder.event_loop);

    /* callback should have fired on channel/event-loop thread */
    ASSERT_INT_EQUALS(1, recorder.invoke_count);
    ASSERT_INT_EQUALS(0, recorder.error_code);
    ASSERT_UINT_EQUALS(234567, recorder.result);
    ASSERT_TRUE(recorder.is_event_loop_thread);

    /* cleanup */
    aws_future_void_release(channel_setup_future);
    aws_future_size_release(recorder.future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_register_channel_callback, s_test_future_register_channel_callback);

static int s_test_future_wait_timeout(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_void *future = aws_future_void_new(alloc);

    uint64_t start_ns;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&start_ns));

    /* The future will never complete, so this should time out and return false */
    ASSERT_FALSE(aws_future_void_wait(future, ONE_SEC_IN_NS));

    uint64_t end_ns;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&end_ns));

    /* Ensure that the wait actually took some time */
    uint64_t duration_ns = end_ns - start_ns;
    ASSERT_TRUE(duration_ns >= (uint64_t)(0.9 * ONE_SEC_IN_NS));

    aws_future_void_release(future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_wait_timeout, s_test_future_wait_timeout)

/* This is a regression test */
static int s_test_future_wait_timeout_max(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    /* Thread will complete the future in 1sec */
    struct aws_future_size *future = s_start_thread_job(alloc, ONE_SEC_IN_NS);

    /* Wait for future to complete, with timeout of UINT64_MAX.
     * Once upon a time, there was a bug where this became a negative number and immediately timed out. */
    bool completed_before_timeout = aws_future_size_wait(future, UINT64_MAX);
    ASSERT_TRUE(completed_before_timeout);

    /* Wait until other thread joins, at which point the future is complete and the callback has fired */
    aws_thread_set_managed_join_timeout_ns(MAX_TIMEOUT_NS);
    ASSERT_SUCCESS(aws_thread_join_all_managed());

    aws_future_size_release(future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_wait_timeout_max, s_test_future_wait_timeout_max)

struct aws_destroyme {
    struct aws_allocator *alloc;
    bool *set_true_on_death;
};

struct aws_destroyme *aws_destroyme_new(struct aws_allocator *alloc, bool *set_true_on_death) {
    struct aws_destroyme *destroyme = aws_mem_calloc(alloc, 1, sizeof(struct aws_destroyme));
    destroyme->alloc = alloc;
    destroyme->set_true_on_death = set_true_on_death;
    *destroyme->set_true_on_death = false;
    return destroyme;
}

void aws_destroyme_destroy(struct aws_destroyme *destroyme) {
    AWS_FATAL_ASSERT(destroyme != NULL && "future should not call destroy() on NULL");
    AWS_FATAL_ASSERT(*destroyme->set_true_on_death == false && "destroy() called multiple times on same object");
    *destroyme->set_true_on_death = true;
    aws_mem_release(destroyme->alloc, destroyme);
}

/* Run through the basics of an AWS_FUTURE_T_POINTER_WITH_DESTROY */
static int s_test_future_pointer_with_destroy(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_destroyme *future = aws_future_destroyme_new(alloc);
    ASSERT_FALSE(aws_future_destroyme_is_done(future));

    /* set result */
    bool original_destroyme_died = false;
    struct aws_destroyme *original_destroyme = aws_destroyme_new(alloc, &original_destroyme_died);
    struct aws_destroyme *destroyme_pointer_copy = original_destroyme;
    aws_future_destroyme_set_result_by_move(future, &original_destroyme);

    ASSERT_NULL(original_destroyme); /* future should NULL this out while taking ownership of the result */
    ASSERT_TRUE(aws_future_destroyme_is_done(future));
    ASSERT_FALSE(original_destroyme_died);

    /* messing with refcount shouldn't trigger destroy */
    aws_future_destroyme_acquire(future);
    aws_future_destroyme_release(future);
    ASSERT_FALSE(original_destroyme_died);

    /* get result (without taking ownership) */
    struct aws_destroyme *destroyme_from_future = aws_future_destroyme_peek_result(future);
    ASSERT_NOT_NULL(destroyme_from_future);
    ASSERT_PTR_EQUALS(destroyme_pointer_copy, destroyme_from_future);
    ASSERT_FALSE(original_destroyme_died);

    /* result should be destroyed along with future */
    aws_future_destroyme_release(future);
    ASSERT_TRUE(original_destroyme_died);

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_pointer_with_destroy, s_test_future_pointer_with_destroy)

struct aws_refcountme {
    struct aws_allocator *alloc;
    struct aws_ref_count ref_count;
    bool *set_true_on_death;
};

static void s_refcountme_destroy(void *user_data) {
    struct aws_refcountme *refcountme = user_data;
    *refcountme->set_true_on_death = true;
    aws_mem_release(refcountme->alloc, refcountme);
}

struct aws_refcountme *aws_refcountme_new(struct aws_allocator *alloc, bool *set_true_on_death) {
    struct aws_refcountme *refcountme = aws_mem_calloc(alloc, 1, sizeof(struct aws_refcountme));
    refcountme->alloc = alloc;
    aws_ref_count_init(&refcountme->ref_count, refcountme, s_refcountme_destroy);
    refcountme->set_true_on_death = set_true_on_death;
    *refcountme->set_true_on_death = false;
    return refcountme;
}

struct aws_refcountme *aws_refcountme_acquire(struct aws_refcountme *refcountme) {
    aws_ref_count_acquire(&refcountme->ref_count);
    return refcountme;
}

/* Most release() functions accept NULL, but not this one, because we want to
 * ensure that aws_future won't pass NULL to the release function */
struct aws_refcountme *aws_refcountme_release(struct aws_refcountme *refcountme) {
    AWS_FATAL_ASSERT(refcountme != NULL && "future should not call release() on NULL");
    AWS_FATAL_ASSERT(*refcountme->set_true_on_death == false && "release() called multiple times on same object");
    *refcountme->set_true_on_death = true;
    aws_mem_release(refcountme->alloc, refcountme);
    return NULL;
}

/* Run through the basics of an AWS_FUTURE_T_POINTER_WITH_RELEASE */
static int s_test_future_pointer_with_release(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_refcountme *future = aws_future_refcountme_new(alloc);
    ASSERT_FALSE(aws_future_refcountme_is_done(future));

    /* set result */
    bool original_refcountme_died = false;
    struct aws_refcountme *original_refcountme = aws_refcountme_new(alloc, &original_refcountme_died);
    struct aws_refcountme *refcountme_pointer_copy = original_refcountme;

    aws_future_refcountme_set_result_by_move(future, &original_refcountme);
    ASSERT_NULL(original_refcountme); /* future should NULL this out while taking ownership of the result */
    ASSERT_TRUE(aws_future_refcountme_is_done(future));
    ASSERT_FALSE(original_refcountme_died);

    /* get result (without taking ownership) */
    struct aws_refcountme *refcountme_from_future = aws_future_refcountme_peek_result(future);
    ASSERT_NOT_NULL(refcountme_from_future);
    ASSERT_PTR_EQUALS(refcountme_pointer_copy, refcountme_from_future);

    /* result should be destroyed along with future */
    aws_future_refcountme_release(future);
    ASSERT_TRUE(original_refcountme_died);

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_pointer_with_release, s_test_future_pointer_with_release)

/* Test that get_result_by_move() transfers ownership */
static int s_test_future_get_result_by_move(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    { /* AWS_FUTURE_T_POINTER_WITH_DESTROY */
        bool destroyme_died = false;
        struct aws_destroyme *original_destroyme = aws_destroyme_new(alloc, &destroyme_died);
        struct aws_future_destroyme *future = aws_future_destroyme_new(alloc);
        aws_future_destroyme_set_result_by_move(future, &original_destroyme);

        /* transfer ownership out of future */
        struct aws_destroyme *destroyme_from_future = aws_future_destroyme_get_result_by_move(future);
        ASSERT_FALSE(destroyme_died);

        /* result should stay alive after future is destroyed */
        aws_future_destroyme_release(future);
        ASSERT_FALSE(destroyme_died);

        /* clean up */
        aws_destroyme_destroy(destroyme_from_future);
        ASSERT_TRUE(destroyme_died);
    }

    { /* AWS_FUTURE_T_POINTER_WITH_RELEASE */
        bool refcountme_died = false;
        struct aws_refcountme *original_refcountme = aws_refcountme_new(alloc, &refcountme_died);
        struct aws_future_refcountme *future = aws_future_refcountme_new(alloc);
        aws_future_refcountme_set_result_by_move(future, &original_refcountme);

        /* transfer ownership out of future */
        struct aws_refcountme *refcountme_from_future = aws_future_refcountme_get_result_by_move(future);
        ASSERT_FALSE(refcountme_died);

        /* result should stay alive after future is destroyed */
        aws_future_refcountme_release(future);
        ASSERT_FALSE(refcountme_died);

        /* clean up */
        aws_refcountme_release(refcountme_from_future);
        ASSERT_TRUE(refcountme_died);
    }

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_get_result_by_move, s_test_future_get_result_by_move)

/* Check that, if an incomplete future dies, the result's destructor doesn't run again.
 * We know this works because the destructor for destroyme and refcountme will assert if NULL is passed in */
static int s_test_future_can_die_incomplete(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_destroyme *future_destroyme = aws_future_destroyme_new(alloc);
    aws_future_destroyme_release(future_destroyme);

    struct aws_future_refcountme *future_refcountme = aws_future_refcountme_new(alloc);
    aws_future_refcountme_release(future_refcountme);

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_can_die_incomplete, s_test_future_can_die_incomplete)

/* Check aws_future<T*> will accept NULL as a result, and not consider it an error,
 * and not try to run the result destructor. */
static int s_test_future_by_pointer_accepts_null_result(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    {
        struct aws_future_destroyme *future = aws_future_destroyme_new(alloc);
        struct aws_destroyme *null_destroyme = NULL;
        aws_future_destroyme_set_result_by_move(future, &null_destroyme);
        ASSERT_TRUE(aws_future_destroyme_is_done(future));
        ASSERT_INT_EQUALS(0, aws_future_destroyme_get_error(future));
        ASSERT_NULL(aws_future_destroyme_peek_result(future));
        aws_future_destroyme_release(future);
    }
    {
        struct aws_future_refcountme *future = aws_future_refcountme_new(alloc);
        struct aws_refcountme *null_refcountme = NULL;
        aws_future_refcountme_set_result_by_move(future, &null_refcountme);
        ASSERT_TRUE(aws_future_refcountme_is_done(future));
        ASSERT_INT_EQUALS(0, aws_future_refcountme_get_error(future));
        ASSERT_NULL(aws_future_refcountme_peek_result(future));
        aws_future_refcountme_release(future);
    }
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_by_pointer_accepts_null_result, s_test_future_by_pointer_accepts_null_result)

/* Check that, if an aws_future<T*> has a result set multiple times, only the 1st result sticks.
 * Any 2nd or 3rd result will just get cleaned up. */
static int s_test_future_set_multiple_times(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_future_destroyme *future = aws_future_destroyme_new(alloc);

    bool result1_destroyed = false;
    struct aws_destroyme *result1 = aws_destroyme_new(alloc, &result1_destroyed);
    struct aws_destroyme *result1_pointer_copy = result1;

    bool result2_destroyed = false;
    struct aws_destroyme *result2 = aws_destroyme_new(alloc, &result2_destroyed);

    bool result3_destroyed = false;
    struct aws_destroyme *result3 = aws_destroyme_new(alloc, &result3_destroyed);

    /* the future now owns result1 */
    aws_future_destroyme_set_result_by_move(future, &result1);
    ASSERT_FALSE(result1_destroyed);

    /* attempt to set result2.
     * the future should continue treating result1 as the result
     * result2 will simply be destroyed */
    aws_future_destroyme_set_result_by_move(future, &result2);
    ASSERT_PTR_EQUALS(result1_pointer_copy, aws_future_destroyme_peek_result(future));
    ASSERT_FALSE(result1_destroyed);
    ASSERT_NULL(result2);
    ASSERT_TRUE(result2_destroyed);

    /* likewise, result3 should be ignored and destroyed */
    aws_future_destroyme_set_result_by_move(future, &result3);
    ASSERT_PTR_EQUALS(result1_pointer_copy, aws_future_destroyme_peek_result(future));
    ASSERT_FALSE(result1_destroyed);
    ASSERT_NULL(result3);
    ASSERT_TRUE(result3_destroyed);

    /* setting an error is ignored, if there's already a result */
    aws_future_destroyme_set_error(future, 999);
    ASSERT_PTR_EQUALS(result1_pointer_copy, aws_future_destroyme_peek_result(future));
    ASSERT_FALSE(result1_destroyed);
    ASSERT_INT_EQUALS(0, aws_future_destroyme_get_error(future));

    /* result1 should finally be destroyed when the future is destroyed */
    aws_future_destroyme_release(future);
    ASSERT_TRUE(result1_destroyed);

    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_set_multiple_times, s_test_future_set_multiple_times)

static int s_test_future_set_error(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_future_destroyme *future = aws_future_destroyme_new(alloc);

    /* Set error code */
    aws_future_destroyme_set_error(future, 999);
    ASSERT_TRUE(aws_future_destroyme_is_done(future));
    ASSERT_INT_EQUALS(999, aws_future_destroyme_get_error(future));

    /* Attempts to change the error should be ignored */
    aws_future_destroyme_set_error(future, 222);
    ASSERT_INT_EQUALS(999, aws_future_destroyme_get_error(future));

    /* Attempts to set a result instead should be ignored (the new result should just get destroyed) */
    bool result_destroyed = false;
    struct aws_destroyme *result = aws_destroyme_new(alloc, &result_destroyed);
    aws_future_destroyme_set_result_by_move(future, &result);
    ASSERT_INT_EQUALS(999, aws_future_destroyme_get_error(future));
    ASSERT_NULL(result);
    ASSERT_TRUE(result_destroyed);

    aws_future_destroyme_release(future);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(future_set_error, s_test_future_set_error)

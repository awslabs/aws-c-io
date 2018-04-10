/*
* Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include <aws/testing/aws_test_harness.h>
#include <aws/io/event_loop.h>
#include <aws/common/mutex.h>

struct event_loop_stopped_args {
    struct aws_mutex mutex;
};

static void on_event_loop_stopped(struct aws_event_loop *event_loop, void *ctx) {
    struct event_loop_stopped_args *stopped_args = (struct event_loop_stopped_args *)ctx;
    aws_mutex_unlock(&stopped_args->mutex);
}

static int test_xthread_scheduled_tasks_execute (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop), "Event loop run failed.");

    struct event_loop_stopped_args stopped_args;
    ASSERT_SUCCESS(aws_mutex_init(&stopped_args.mutex, allocator), "Mutex initialization failed");

    /* test code here */

    ASSERT_SUCCESS(aws_mutex_lock(&stopped_args.mutex), "Mutex lock failed");
    ASSERT_SUCCESS(aws_event_loop_stop(event_loop, on_event_loop_stopped, &stopped_args), "Event loop stop failed.");

    /*using it as a semaphore here. */
    ASSERT_SUCCESS(aws_mutex_lock(&stopped_args.mutex), "Mutex lock failed");

    /* now this should be safe. */
    aws_event_loop_destroy(event_loop);
    aws_mutex_clean_up(&stopped_args.mutex);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(xthread_scheduled_tasks_execute, test_xthread_scheduled_tasks_execute)
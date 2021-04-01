/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/* clang-format off */
#define STOP_TASK_FN_PTR
#include "preamble.h"

static void s_stop_task(struct aws_task *task, void *args, enum aws_task_status status) {

    (void)task;
    struct aws_event_loop *event_loop = args;
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    /* now okay to reschedule stop tasks. */
    _(unwrap &epoll_loop->stop_task_ptr)
    aws_atomic_store_ptr(&epoll_loop->stop_task_ptr, NULL);
    _(wrap &epoll_loop->stop_task_ptr)
    if (status == AWS_TASK_STATUS_RUN_READY) {
        /*
         * this allows the event loop to invoke the callback once the event loop has completed.
         */
        _(unwrap epoll_loop::status)
        epoll_loop->should_continue = false;
        _(wrap epoll_loop::status)
    }
}

static int s_stop(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
) {
    _(assert \always_by_claim(c_event_loop, event_loop))
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    void *expected_ptr = NULL;
    _(unwrap &epoll_loop->stop_task_ptr)
    bool update_succeeded =
        aws_atomic_compare_exchange_ptr(&epoll_loop->stop_task_ptr, &expected_ptr, &epoll_loop->stop_task);
    _(wrap &epoll_loop->stop_task_ptr)
    if (!update_succeeded) {
        /* the stop task is already scheduled. */
        return AWS_OP_SUCCESS;
    }
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);
    aws_task_init(&epoll_loop->stop_task, s_stop_task, event_loop, "epoll_event_loop_stop");
    s_schedule_task_now(event_loop, &epoll_loop->stop_task _(ghost c_event_loop) _(ghost c_mutex));

    return AWS_OP_SUCCESS;
}

int aws_thread_join(struct aws_thread *thread
    _(ghost struct aws_event_loop *event_loop) _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex))
)
    _(requires c_event_loop != c_mutex)
    _(requires \wrapped0(c_event_loop) && \claims(c_event_loop, event_loop->\closed) && \claims_object(c_event_loop, event_loop))
    _(writes c_event_loop, event_loop)
    _(ensures !c_event_loop->\closed)
    _(ensures \wrapped0(event_loop) && \nested(epoll_loop_of(event_loop)))
    _(ensures ownership_of_epoll_loop_objects(epoll_loop_of(event_loop)))
    _(ensures epoll_loop_of(event_loop)->task_pre_queue_mutex.locked == 0)
    _(maintains \malloc_root(epoll_loop_of(event_loop)))
    _(maintains \wrapped0(c_mutex) && \claims_object(c_mutex, &epoll_loop_of(event_loop)->task_pre_queue_mutex))
;

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex))
) {
    struct epoll_loop *epoll_loop = _(by_claim c_event_loop) event_loop->impl_data;
    int result = aws_thread_join(&epoll_loop->thread_created_on _(ghost event_loop) _(ghost c_event_loop) _(ghost c_mutex));
    aws_thread_decrement_unjoined_count();
    return result;
}

int aws_thread_launch(
    struct aws_thread *thread,
    void (*func)(void *arg),
    void *arg,
    const struct aws_thread_options *options)
    _(requires \wrapped0(event_loop_of(arg)))
    _(requires func->\valid)
;

/* Not modeled: thread launch ownership change semantics */
void dummy_main_loop(void *arg); /*< VCC change */

static int s_run(struct aws_event_loop *event_loop _(ghost \claim(c_mutex))) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);

    epoll_loop->should_continue = true;
    aws_thread_increment_unjoined_count();
    if (aws_thread_launch(&epoll_loop->thread_created_on, /*&s_main_loop*/&dummy_main_loop, event_loop, &epoll_loop->thread_options)) {
        aws_thread_decrement_unjoined_count();
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: thread creation failed.", (void *)event_loop);
        epoll_loop->should_continue = false;
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
/* clang-format on */

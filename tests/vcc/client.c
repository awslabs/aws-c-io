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
#include "preamble.h"

struct aws_allocator *aws_default_allocator()
    _(ensures \wrapped(\result))
;

uint64_t next_timestamp();

int clock(uint64_t *timestamp)
    _(writes timestamp)
{
    *timestamp = next_timestamp();
    return AWS_OP_SUCCESS;
}

void test_new_destroy()
{
    struct aws_allocator *alloc = aws_default_allocator();
    _(ghost \claim c_mutex)
    struct aws_event_loop *event_loop = aws_event_loop_new_default(alloc, clock, _(out c_mutex));
    if (!event_loop) return;
    _(ghost \claim c_event_loop;)
    _(ghost c_event_loop = \make_claim({event_loop}, event_loop->\closed);)
    s_destroy(event_loop _(ghost c_event_loop) _(ghost c_mutex));
}

void on_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data _(ghost \claim(c))
);

void test_subscribe_unsubscribe(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    _(always c_event_loop, event_loop->\closed)
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(writes event_loop)
    _(updates &epoll_loop_of(event_loop)->scheduler)
{
    struct aws_io_handle *handle = malloc(sizeof(struct aws_io_handle));
    if (!handle) return;
    handle->data.fd = 1; /* model successful open() */
    _(wrap handle)
    int err = s_subscribe_to_io_events(event_loop, handle, 0, on_event, NULL, _(ghost c_event_loop));
    if (err) {
      return;
    }
    _(assert wf_cio_handle(handle))
    _(assert \wrapped((struct epoll_event_data *)handle->additional_data))
    _(assert ((struct epoll_event_data *)handle->additional_data)->\owner == \me)
    s_unsubscribe_from_io_events(event_loop, handle _(ghost c_event_loop) _(ghost c_mutex));
}

void task_fn(struct aws_task *task, void *arg, enum aws_task_status) {
    (void)task;
    (void)arg;
}

void test_schedule_cancel(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    _(requires \wrapped(event_loop))
    _(always c_event_loop, event_loop->\closed)
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(updates &epoll_loop_of(event_loop)->scheduler)
{
    struct aws_task *task = malloc(sizeof(struct aws_task));
    if (!task) return;
    aws_task_init(task, task_fn, NULL, "test_task");
    s_schedule_task_now(event_loop, task _(ghost c_event_loop) _(ghost c_mutex));
    s_cancel_task(event_loop, task);
}
/* clang-format on */

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

/* not in preamble because we specialize for reading-from a uint64_t var (as
used by `s_schedule_task_common`) */
ssize_t write(int fd, void *bytes, size_t nbytes)
    _(requires valid_fd(fd))
    _(requires nbytes == sizeof(uint64_t))
    _(requires \thread_local((uint64_t *)bytes))
;

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    _(always c_event_loop, event_loop->\closed)
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(requires \thread_local(task))
    _(requires \wrapped(task))
    _(requires task->fn->\valid)
    _(writes task)
    _(updates &epoll_loop_of(event_loop)->scheduler)
{
    _(assert \always_by_claim(c_event_loop, event_loop))
    _(assert \active_claim(c_event_loop))
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    _(assert \inv(epoll_loop))
    _(assert epoll_loop->\closed)
    _(assert epoll_loop->write_task_handle.\closed)
    _(assert \inv(&epoll_loop->write_task_handle))
    _(assert valid_fd(epoll_loop->write_task_handle.data.fd))

    /* if event loop and the caller are the same thread, just schedule and be done with it. */
    if (s_is_on_callers_thread(event_loop _(ghost c_event_loop))) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: scheduling task %p in-thread for timestamp %llu",
            (void *)event_loop,
            (void *)task,
            (unsigned long long)run_at_nanos);
        if (run_at_nanos == 0) {
            /* zero denotes "now" task */
            aws_task_scheduler_schedule_now(&epoll_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&epoll_loop->scheduler, task, run_at_nanos);
        }
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Scheduling task %p cross-thread for timestamp %llu",
        (void *)event_loop,
        (void *)task,
        (unsigned long long)run_at_nanos);
    _(unwrap task)
    task->timestamp = run_at_nanos;
    _(wrap task)
    aws_mutex_lock(&epoll_loop->task_pre_queue_mutex _(ghost c_mutex));
    _(assert epoll_loop->task_pre_queue.\owner == \me)

    uint64_t counter = 1;

    bool is_first_task = aws_linked_list_empty(&epoll_loop->task_pre_queue);

    aws_linked_list_push_back(&epoll_loop->task_pre_queue, &task->node _(ghost task));

    /* if the list was not empty, we already have a pending read on the pipe/eventfd, no need to write again. */
    if (is_first_task) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Waking up event-loop thread", (void *)event_loop);

        /* If the write fails because the buffer is full, we don't actually care because that means there's a pending
         * read on the pipe/eventfd and thus the event loop will end up checking to see if something has been queued.*/
        _(assert \active_claim(c_event_loop)) /*< implies write_task_handle.data.fd is a valid fd
                                                 ==> event_loop->\closed
                                                 ==> epoll_loop->\closed ==> \inv(epoll_loop)
                                                 ==> epoll_loop->write_task_handle.\closed ==> \inv(&epoll_loop->write_task_handle) */
        ssize_t do_not_care = write(_(by_claim c_event_loop) epoll_loop->write_task_handle.data.fd, (void *)&counter, sizeof(counter));
        (void)do_not_care;
    }

    aws_mutex_unlock(&epoll_loop->task_pre_queue_mutex _(ghost c_mutex));
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */ _(ghost c_event_loop) _(ghost c_mutex));
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
) {
    s_schedule_task_common(event_loop, task, run_at_nanos _(ghost c_event_loop) _(ghost c_mutex));
}
/* clang-format on */

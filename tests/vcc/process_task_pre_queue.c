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

/* `read` not in preamble because we specialize for reading-into a uint64_t
var (as used by `s_process_task_pre_queue`) */
ssize_t read(int fd, void *buf, uint64_t count)
    _(requires valid_fd(fd))
    _(requires count == sizeof(uint64_t))
    _(writes (uint64_t *)buf)
;

static void s_process_task_pre_queue(struct aws_event_loop *event_loop _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex))) {
    _(assert \always_by_claim(c_event_loop, event_loop))
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    _(assert \inv(epoll_loop))

    if (!epoll_loop->should_process_task_pre_queue) {
        return;
    }

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: processing cross-thread tasks", (void *)event_loop);
    epoll_loop->should_process_task_pre_queue = false;

    struct aws_linked_list task_pre_queue;
    aws_linked_list_init(&task_pre_queue);
    _(wrap(&task_pre_queue.head))
    _(wrap(&task_pre_queue.tail))
    _(wrap(&task_pre_queue))

    uint64_t count_ignore = 0;

    aws_mutex_lock(&epoll_loop->task_pre_queue_mutex _(ghost c_mutex));

    /* several tasks could theoretically have been written (though this should never happen), make sure we drain the
     * eventfd/pipe. */
    while (read(epoll_loop->read_task_handle.data.fd, &count_ignore, sizeof(count_ignore)) > -1)
        _(invariant \thread_local(&epoll_loop->read_task_handle))
        _(invariant (&epoll_loop->read_task_handle)->\closed)
        _(invariant \inv(&epoll_loop->read_task_handle))
        _(invariant \wrapped(&epoll_loop->scheduler))
        _(writes &count_ignore)
    {
    }

    aws_linked_list_swap_contents(&epoll_loop->task_pre_queue, &task_pre_queue);

    aws_mutex_unlock(&epoll_loop->task_pre_queue_mutex _(ghost c_mutex));

    while (!aws_linked_list_empty(&task_pre_queue))
        _(invariant 0 <= task_pre_queue.length)
        _(invariant \wrapped(&task_pre_queue))
        _(invariant \wrapped(&epoll_loop->scheduler))
        _(writes &task_pre_queue, &epoll_loop->scheduler)
    {
        _(ghost struct aws_task *t)
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&task_pre_queue _(out t));
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: task %p pulled to event-loop, scheduling now.",
            (void *)event_loop,
            (void *)task);
        /* Timestamp 0 is used to denote "now" tasks */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&epoll_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&epoll_loop->scheduler, task, task->timestamp);
        }
    }
    _(unwrap(&task_pre_queue))
    _(unwrap(&task_pre_queue.head))
    _(unwrap(&task_pre_queue.tail))
}
/* clang-format on */

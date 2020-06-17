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
#define UNSUB_TASK_FN_PTR
#include "preamble.h"

void s_unsubscribe_cleanup_task(struct aws_task *task, void *arg, enum aws_task_status status)
    _(requires \malloc_root((struct epoll_event_data *)arg))
    _(writes \extent((struct epoll_event_data *)arg))
{
    (void)task;
    (void)status;
    struct epoll_event_data *event_data = (struct epoll_event_data *)arg;
    aws_mem_release(event_data->alloc, (void *)event_data);
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP, "id=%p: un-subscribing from events on fd %d", (void *)event_loop, handle->data.fd);
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    AWS_ASSERT(handle->additional_data);
    struct epoll_event_data *additional_handle_data = handle->additional_data;
    _(assert \wrapped(additional_handle_data))
    _(assert \inv(additional_handle_data))

    struct epoll_event dummy_event;

    if (AWS_UNLIKELY(epoll_ctl(epoll_loop->epoll_fd, EPOLL_CTL_DEL, handle->data.fd, &dummy_event /*ignored*/))) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: failed to un-subscribe from events on fd %d",
            (void *)event_loop,
            handle->data.fd);
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    /* We can't clean up yet, because we have schedule tasks and more events to process,
     * mark it as unsubscribed and schedule a cleanup task. */

    _(unwrap(additional_handle_data))
    _(assert handle->\owner != additional_handle_data)
    additional_handle_data->is_subscribed = false;

    aws_task_init(
        &additional_handle_data->cleanup_task,
        s_unsubscribe_cleanup_task,
        additional_handle_data,
        "epoll_event_loop_unsubscribe_cleanup");
    s_schedule_task_now(event_loop, &additional_handle_data->cleanup_task _(ghost c_event_loop) _(ghost c_mutex));

    _(unwrap(handle))
    handle->additional_data = NULL;
    _(assert handle->\owner == \me)

    return AWS_OP_SUCCESS;
}
/* clang-format on */

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

static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn_ptr on_event, /*< VCC change: fnptr */
    void *user_data
    _(ghost \claim(c_event_loop))
) {
    _(assert \always_by_claim(c_event_loop, event_loop))

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: subscribing to events on fd %d", (void *)event_loop, handle->data.fd);
    struct epoll_event_data *epoll_event_data = aws_mem_calloc(event_loop->alloc, 1, sizeof(struct epoll_event_data));
    _(unwrap handle)
    handle->additional_data = epoll_event_data;

    if (!epoll_event_data) {
        return AWS_OP_ERR;
    }

    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;
    epoll_event_data->alloc = event_loop->alloc;
    epoll_event_data->user_data = user_data;
    epoll_event_data->handle = handle;
    epoll_event_data->on_event = on_event;
    epoll_event_data->is_subscribed = true;

    /*everyone is always registered for edge-triggered, hang up, remote hang up, errors. */
    uint32_t event_mask = EPOLLET | EPOLLHUP | EPOLLRDHUP | EPOLLERR;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        event_mask |= EPOLLIN;
    }

    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        event_mask |= EPOLLOUT;
    }

    /* this guy is copied by epoll_ctl */
    /* VCC change: rewrite struct initialization */
#if 0
    struct epoll_event epoll_event = {
        .data = {.ptr = epoll_event_data},
        .events = event_mask,
    };
#else
    struct epoll_event epoll_event;
    epoll_event.data.ptr = epoll_event_data;
    epoll_event.events = event_mask;
#endif
 
    if (epoll_ctl(_(by_claim c_event_loop) epoll_loop->epoll_fd, EPOLL_CTL_ADD, handle->data.fd, &epoll_event)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_EVENT_LOOP, "id=%p: failed to subscribe to events on fd %d", (void *)event_loop, handle->data.fd);
        handle->additional_data = NULL;
        aws_mem_release(event_loop->alloc, epoll_event_data);
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }
    _(wrap(handle))
    _(wrap(&epoll_event_data->cleanup_task.node))
    _(wrap(&epoll_event_data->cleanup_task.priority_queue_node))
    _(wrap(&epoll_event_data->cleanup_task))
    _(wrap(epoll_event_data))

    return AWS_OP_SUCCESS;
}
/* clang-format on */

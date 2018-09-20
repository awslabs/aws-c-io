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

#include <aws/io/pipe.h>

#include <aws/io/event_loop.h>

#ifdef __GLIBC__
#    define __USE_GNU
#endif

/* TODO: move this detection to CMAKE and a config header */
#if !defined(COMPAT_MODE) && defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 9
#    define HAVE_PIPE2 1
#else
#    define HAVE_PIPE2 0
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

struct read_end_impl {
    struct aws_allocator *alloc;
    struct aws_io_handle handle;
    struct aws_event_loop *event_loop;
    aws_pipe_on_readable_fn *on_readable_user_callback;
    void *on_readable_user_data;
    bool is_subscribed;
};

struct write_request {
    struct aws_byte_cursor cursor;
    size_t num_bytes_written;
    aws_pipe_on_write_complete_fn *user_callback;
    void *user_data;
    struct aws_linked_list_node list_node;

    /* True if the write-end is cleaned up while the user callback is being invoked */
    bool did_user_callback_clean_up_write_end;
};

struct write_end_impl {
    struct aws_allocator *alloc;
    struct aws_io_handle handle;
    struct aws_event_loop *event_loop;
    struct aws_linked_list write_list;

    /* Valid while invoking user callback on a completed write request. */
    struct write_request *currently_invoking_write_callback;

    bool is_writable;

    /* Future optimization idea: avoid an allocation on each write by keeping 1 pre-allocated write_request around
     * and re-using it whenever possible */
};

static void s_write_end_on_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data);

static int s_translate_posix_error(int err) {
    assert(err);

    switch (err) {
        case EPIPE:
            return AWS_IO_BROKEN_PIPE;
        default:
            return AWS_IO_SYS_CALL_FAILURE;
    }
}

static int s_raise_posix_error(int err) {
    return aws_raise_error(s_translate_posix_error(err));
}

int aws_open_nonblocking_posix_pipe(int pipe_fds[2]) {
    int err;

#if HAVE_PIPE2
    err = pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC);
    if (err) {
        return s_raise_posix_error(err);
    }

    return AWS_OP_SUCCESS;
#else
    err = pipe(pipe_fds);
    if (err) {
        return s_raise_posix_error(err);
    }

    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(pipe_fds[i], F_GETFL);
        if (flags == -1) {
            s_raise_posix_error(err);
            goto error;
        }

        flags |= O_NONBLOCK | O_CLOEXEC;
        if (fcntl(pipe_fds[i], F_SETFL, flags) == -1) {
            s_raise_posix_error(err);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;
error:
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return AWS_OP_ERR;
#endif
}

int aws_pipe_init(
    struct aws_pipe_read_end *read_end,
    struct aws_event_loop *read_end_event_loop,
    struct aws_pipe_write_end *write_end,
    struct aws_event_loop *write_end_event_loop,
    struct aws_allocator *allocator) {

    assert(read_end);
    assert(read_end_event_loop);
    assert(write_end);
    assert(write_end_event_loop);
    assert(allocator);

    AWS_ZERO_STRUCT(*read_end);
    AWS_ZERO_STRUCT(*write_end);

    struct read_end_impl *read_impl = NULL;
    struct write_end_impl *write_impl = NULL;
    int err;

    /* Open pipe */
    int pipe_fds[2];
    err = aws_open_nonblocking_posix_pipe(pipe_fds);
    if (err) {
        return s_raise_posix_error(err);
    }

    /* Init read-end */
    read_impl = aws_mem_acquire(allocator, sizeof(struct read_end_impl));
    if (!read_impl) {
        goto error;
    }

    AWS_ZERO_STRUCT(*read_impl);
    read_impl->alloc = allocator;
    read_impl->handle.data.fd = pipe_fds[0];
    read_impl->event_loop = read_end_event_loop;

    /* Init write-end */
    write_impl = aws_mem_acquire(allocator, sizeof(struct write_end_impl));
    if (!write_impl) {
        goto error;
    }

    AWS_ZERO_STRUCT(*write_impl);
    write_impl->alloc = allocator;
    write_impl->handle.data.fd = pipe_fds[1];
    write_impl->event_loop = write_end_event_loop;
    write_impl->is_writable = true; /* Assume pipe is writable to start. Even if it's not, things shouldn't break */
    aws_linked_list_init(&write_impl->write_list);

    err = aws_event_loop_subscribe_to_io_events(
        write_end_event_loop, &write_impl->handle, AWS_IO_EVENT_TYPE_WRITABLE, s_write_end_on_event, write_end);
    if (err) {
        goto error;
    }

    /* Success */
    read_end->impl_data = read_impl;
    write_end->impl_data = write_impl;

    return AWS_OP_SUCCESS;

error:
    close(pipe_fds[0]);
    close(pipe_fds[1]);

    if (read_impl) {
        aws_mem_release(allocator, read_impl);
    }

    if (write_impl) {
        aws_mem_release(allocator, write_impl);
    }

    return AWS_OP_ERR;
}

int aws_pipe_clean_up_read_end(struct aws_pipe_read_end *read_end) {
    struct read_end_impl *read_impl = read_end->impl_data;
    assert(read_impl);

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (read_impl->is_subscribed) {
        int err = aws_pipe_unsubscribe_from_readable_events(read_end);
        if (err) {
            return AWS_OP_ERR;
        }
    }

    aws_mem_release(read_impl->alloc, read_impl);
    AWS_ZERO_STRUCT(*read_end);
    return AWS_OP_SUCCESS;
}

struct aws_event_loop *aws_pipe_get_read_end_event_loop(const struct aws_pipe_read_end *read_end) {
    const struct read_end_impl *read_impl = read_end->impl_data;
    assert(read_impl);

    return read_impl->event_loop;
}

struct aws_event_loop *aws_pipe_get_write_end_event_loop(const struct aws_pipe_write_end *write_end) {
    const struct write_end_impl *write_impl = write_end->impl_data;
    assert(write_impl);

    return write_impl->event_loop;
}

int aws_pipe_read(struct aws_pipe_read_end *read_end, uint8_t *dst, size_t dst_size, size_t *num_bytes_read) {
    struct read_end_impl *read_impl = read_end->impl_data;
    assert(read_impl);
    assert(dst);

    if (num_bytes_read) {
        *num_bytes_read = 0;
    }

    ssize_t read_val = read(read_impl->handle.data.fd, dst, dst_size);

    if (read_val < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
        }
        return s_raise_posix_error(errno);
    }

    if (num_bytes_read) {
        *num_bytes_read = read_val;
    }

    return AWS_OP_SUCCESS;
}

static void s_read_end_on_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    /* Note that it should be impossible for this to run after read-end has been unsubscribed or cleaned up */
    struct aws_pipe_read_end *read_end = user_data;
    struct read_end_impl *read_impl = read_end->impl_data;
    assert(read_impl);
    assert(read_impl->event_loop == event_loop);
    assert(&read_impl->handle == handle);
    assert(read_impl->is_subscribed);
    assert(events != 0);

    int error_code = (events == AWS_IO_EVENT_TYPE_READABLE) ? AWS_ERROR_SUCCESS : AWS_IO_BROKEN_PIPE;

    read_impl->on_readable_user_callback(read_end, error_code, read_impl->on_readable_user_data);
}

int aws_pipe_subscribe_to_readable_events(
    struct aws_pipe_read_end *read_end,
    aws_pipe_on_readable_fn *on_readable,
    void *user_data) {

    struct read_end_impl *read_impl = read_end->impl_data;
    assert(read_impl);
    assert(on_readable);

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (read_impl->is_subscribed) {
        return aws_raise_error(AWS_ERROR_IO_ALREADY_SUBSCRIBED);
    }

    int err = aws_event_loop_subscribe_to_io_events(
        read_impl->event_loop, &read_impl->handle, AWS_IO_EVENT_TYPE_READABLE, s_read_end_on_event, read_end);
    if (err) {
        return AWS_OP_ERR;
    }

    read_impl->is_subscribed = true;
    read_impl->on_readable_user_callback = on_readable;
    read_impl->on_readable_user_data = user_data;

    return AWS_OP_SUCCESS;
}

int aws_pipe_unsubscribe_from_readable_events(struct aws_pipe_read_end *read_end) {
    struct read_end_impl *read_impl = read_end->impl_data;
    assert(read_impl);

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!read_impl->is_subscribed) {
        return aws_raise_error(AWS_ERROR_IO_NOT_SUBSCRIBED);
    }

    int err = aws_event_loop_unsubscribe_from_io_events(read_impl->event_loop, &read_impl->handle);
    if (err) {
        return AWS_OP_ERR;
    }

    read_impl->is_subscribed = false;
    read_impl->on_readable_user_callback = NULL;
    read_impl->on_readable_user_data = NULL;

    return AWS_OP_SUCCESS;
}

/* Pop front write request, invoke its callback, and delete it.
 * Returns whether the callback resulted in the write-end getting cleaned up */
static bool s_write_end_complete_front_write_request(struct aws_pipe_write_end *write_end, int status) {
    struct write_end_impl *write_impl = write_end->impl_data;

    assert(!aws_linked_list_empty(&write_impl->write_list));
    struct aws_linked_list_node *node = aws_linked_list_pop_front(&write_impl->write_list);
    struct write_request *request = AWS_CONTAINER_OF(node, struct write_request, list_node);

    struct aws_allocator *alloc = write_impl->alloc;

    /* Let the write-end know that a callback is in process, so the write-end can inform the callback
     * whether it resulted in clean_up() being called. */
    bool write_end_cleaned_up_during_callback = false;
    struct write_request *prev_invoking_request = write_impl->currently_invoking_write_callback;
    write_impl->currently_invoking_write_callback = request;

    if (request->user_callback) {
        request->user_callback(write_end, status, request->num_bytes_written, request->user_data);
        write_end_cleaned_up_during_callback = request->did_user_callback_clean_up_write_end;
    }

    if (!write_end_cleaned_up_during_callback) {
        write_impl->currently_invoking_write_callback = prev_invoking_request;
    }

    aws_mem_release(alloc, request);

    return write_end_cleaned_up_during_callback;
}

/* Process write requests as long as the pipe remains writable */
static void s_write_end_process_requests(struct aws_pipe_write_end *write_end) {
    struct write_end_impl *write_impl = write_end->impl_data;
    assert(write_impl);

    while (!aws_linked_list_empty(&write_impl->write_list)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&write_impl->write_list);
        struct write_request *request = AWS_CONTAINER_OF(node, struct write_request, list_node);

        int completed_write_status = AWS_ERROR_SUCCESS;

        if (request->cursor.len > 0) {
            ssize_t write_val = write(write_impl->handle.data.fd, request->cursor.ptr, request->cursor.len);

            if (write_val < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* The pipe is no longer writable. Bail out */
                    write_impl->is_writable = false;
                    return;
                }

                /* A non-recoverable error occurred during this write */
                completed_write_status = s_translate_posix_error(errno);

            } else {
                request->num_bytes_written += write_val;
                aws_byte_cursor_advance(&request->cursor, write_val);

                if (request->cursor.len > 0) {
                    /* There was a partial write, loop again to try and write the rest. */
                    continue;
                }
            }
        }

        /* If we got this far in the loop, then the write request is complete.
         * Note that the callback may result in the pipe being cleaned up. */
        bool write_end_cleaned_up = s_write_end_complete_front_write_request(write_end, completed_write_status);
        if (write_end_cleaned_up) {
            /* Bail out! Any remaining requests were canceled during clean_up() */
            return;
        }
    }
}

/* Handle events on the write-end's file handle */
static void s_write_end_on_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    /* Note that it should be impossible for this to run after read-end has been unsubscribed or cleaned up */
    struct aws_pipe_write_end *write_end = user_data;
    struct write_end_impl *write_impl = write_end->impl_data;
    assert(write_impl);
    assert(write_impl->event_loop == event_loop);
    assert(&write_impl->handle == handle);

    /* Only care about the writable event. */
    if ((events & AWS_IO_EVENT_TYPE_WRITABLE) == 0) {
        return;
    }

    write_impl->is_writable = true;

    s_write_end_process_requests(write_end);
}

int aws_pipe_write(
    struct aws_pipe_write_end *write_end,
    const uint8_t *src,
    size_t src_size,
    aws_pipe_on_write_complete_fn *on_complete,
    void *user_data) {

    assert(src);

    struct write_end_impl *write_impl = write_end->impl_data;
    assert(write_impl);

    if (!aws_event_loop_thread_is_callers_thread(write_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    struct write_request *request = aws_mem_acquire(write_impl->alloc, sizeof(struct write_request));
    if (!request) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*request);
    request->cursor = aws_byte_cursor_from_array(src, src_size);
    request->user_callback = on_complete;
    request->user_data = user_data;

    aws_linked_list_push_back(&write_impl->write_list, &request->list_node);

    /* If the pipe is writable, process the request (unless pipe is already in the middle of processing, which could
     * happen if a this aws_pipe_write() call was made by another write's completion callback */
    if (write_impl->is_writable && !write_impl->currently_invoking_write_callback) {
        s_write_end_process_requests(write_end);
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_clean_up_write_end(struct aws_pipe_write_end *write_end) {
    struct write_end_impl *write_impl = write_end->impl_data;
    assert(write_impl);

    if (!aws_event_loop_thread_is_callers_thread(write_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    int err = aws_event_loop_unsubscribe_from_io_events(write_impl->event_loop, &write_impl->handle);
    if (err) {
        return AWS_OP_ERR;
    }

    /* If a request callback is currently being invoked, let it know that the write-end was cleaned up */
    if (write_impl->currently_invoking_write_callback) {
        write_impl->currently_invoking_write_callback->did_user_callback_clean_up_write_end = true;
    }

    /* Force any outstanding write requests to complete with an error status. */
    while (!aws_linked_list_empty(&write_impl->write_list)) {
        s_write_end_complete_front_write_request(write_end, AWS_IO_BROKEN_PIPE);
    }

    aws_mem_release(write_impl->alloc, write_impl);
    AWS_ZERO_STRUCT(*write_end);
    return AWS_OP_SUCCESS;
}

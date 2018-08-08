#ifndef AWS_IO_PIPE_H
#define AWS_IO_PIPE_H

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

#include <aws/common/common.h>
#include <aws/io/exports.h>

struct aws_pipe_read_end {
    void *impl_data;
};

struct aws_pipe_write_end {
    void *impl_data;
};

/**
 * Called when the read-end is finished cleaning up.
 * This call is always made on the read-end's event-loop thread.
 */
typedef void(aws_pipe_on_read_end_closed_fn)(struct aws_pipe_read_end *read_end, void *user_data);

/**
 * Called when the write-end is finished cleaning up.
 * This call is always made on the write-end's event-loop thread.
 */
typedef void(aws_pipe_on_write_end_closed_fn)(struct aws_pipe_write_end *write_end, void *user_data);

/**
 * Called when events occur on the read end of the pipe.
 * `events` contains flags corresponding to `aws_io_event_type` values.
 * `user_data` corresponds to the `user_data` passed into aws_pipe_subscribe_to_read_events().
 * This call is always made on the read-end's event-loop thread.
 */
typedef void(aws_pipe_on_read_event_fn)(struct aws_pipe_read_end *read_end, int events, void *user_data);

/**
 * Called when the write initialized by aws_pipe_write() completes.
 * `write_result` contains AWS_ERROR_SUCCESS or a code corresponding to the error.
 * `num_bytes_written` contains the number of bytes successfully transferred.
 * `user_data` corresponds to the `user_data` passed into aws_pipe_write().
 * This call is always made on the write-end's event-loop thread.
 */
typedef void(aws_pipe_on_write_complete_fn)(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens an OS specific bidirectional pipe.
 * The read direction is stored in read_end. Write direction is stored in write_end.
 * Each end must be connected to an event-loop, and further calls to each end must happen on that event-loop's thread.
 */
AWS_IO_API
int aws_pipe_init(
    struct aws_pipe_read_end *read_end,
    struct aws_event_loop *read_end_event_loop,
    struct aws_pipe_write_end *write_end,
    struct aws_event_loop *write_end_event_loop,
    struct aws_allocator *allocator);

/**
 * Clean up the read-end of the pipe.
 * This must be called on the thread of the connected event-loop.
 */
AWS_IO_API
int aws_pipe_clean_up_read_end(
    struct aws_pipe_read_end *read_end,
    aws_pipe_on_read_end_closed_fn *on_closed,
    void *user_data);

/**
 * Clean up the write-end of the pipe.
 * This must be called on the thread of the connected event-loop.
 */
AWS_IO_API
int aws_pipe_clean_up_write_end(
    struct aws_pipe_write_end *write_end,
    aws_pipe_on_write_end_closed_fn *on_closed,
    void *user_data);

/**
 * Get the event-loop connected to the read-end of the pipe.
 * This may be called on any thread.
 */
AWS_IO_API
struct aws_event_loop *aws_pipe_get_read_end_event_loop(const struct aws_pipe_read_end *read_end);

/**
 * Get the event-loop connected to the write-end of the pipe.
 * This may be called on any thread.
 */
AWS_IO_API
struct aws_event_loop *aws_pipe_get_write_end_event_loop(const struct aws_pipe_write_end *write_end);

/**
 * Initiates an asynchrous write from `src` buffer to the pipe.
 * Up to `src_size` bytes will be written.
 * `on_complete` will be called on the event-loop thread when the operation completes.
 * Multiple asynchronous writes may be active at a time, they will be written in the order they are received.
 * This must be called on the thread of the connected event-loop.
 */
AWS_IO_API
int aws_pipe_write(
    struct aws_pipe_write_end *write_end,
    const uint8_t *src,
    size_t src_size,
    aws_pipe_on_write_complete_fn *on_complete,
    void *user_data);

/**
 * Reads data from the pipe to the `dst` buffer.
 * Up to `dst_size` bytes will be read.
 * The number of bytes successfully read will be stored in `num_bytes_read`.
 * This function never blocks. If a block would be required to read then AWS_OP_ERR is
 * returned and aws_last_error() code will be AWS_IO_READ_WOULD_BLOCK.
 * This must be called on the thread of the connected event-loop.
 */
AWS_IO_API
int aws_pipe_read(struct aws_pipe_read_end *read_end, uint8_t *dst, size_t dst_size, size_t *num_bytes_read);

/**
 * Subscribe to be notified of events affecting the read-end of the pipe.
 * This is useful for learning when the pipe has data that can be read.
 * When events occurs, `on_read_event` is called on the event-loop's thread.
 * This must be called on the thread of the connected event-loop.
 */
AWS_IO_API
int aws_pipe_subscribe_to_read_events(
    struct aws_pipe_read_end *read_end,
    aws_pipe_on_read_event_fn *on_read_event,
    void *user_data);

/**
 * Stop receiving notifications about events affecting the read-end of the pipe.
 * This must be called on the thread of the connected event-loop.
 */
AWS_IO_API
int aws_pipe_unsubscribe_from_read_events(struct aws_pipe_read_end *read_end);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_PIPE_H */

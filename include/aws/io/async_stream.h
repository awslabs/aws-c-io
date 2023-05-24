#ifndef AWS_IO_ASYNC_STREAM_H
#define AWS_IO_ASYNC_STREAM_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

#include <aws/common/ref_count.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_byte_buf;

struct aws_async_stream {
    const struct aws_async_stream_vtable *vtable;
    struct aws_allocator *alloc;
    struct aws_ref_count ref_count;
    void *impl;
};

struct aws_async_stream_vtable {
    void (*destroy)(struct aws_async_stream *stream);
    struct aws_future_bool *(*read_once)(struct aws_async_stream *stream, struct aws_byte_buf *dest);
};

AWS_EXTERN_C_BEGIN

/**
 * Initialize aws_async_stream "base class"
 */
AWS_IO_API
void aws_async_stream_init_base(
    struct aws_async_stream *stream,
    struct aws_allocator *alloc,
    const struct aws_async_stream_vtable *vtable,
    void *impl);

/**
 * Increment reference count.
 * You may pass in NULL (has no effect).
 * Returns whatever pointer was passed in.
 */
AWS_IO_API
struct aws_async_stream *aws_async_stream_acquire(struct aws_async_stream *stream);

/**
 * Decrement reference count.
 * You may pass in NULL (has no effect).
 * Always returns NULL.
 */
AWS_IO_API
struct aws_async_stream *aws_async_stream_release(struct aws_async_stream *stream);

/**
 * Read once from the async stream into the buffer.
 * The read completes when at least 1 byte is read, the buffer is full, or EOF is reached.
 * The read may complete synchronously, and may complete on another thread.
 * Returns aws_future<bool>, which on completion holds a bool indicating EOF or an error code.
 */
AWS_IO_API
struct aws_future_bool *aws_async_stream_read_once(struct aws_async_stream *stream, struct aws_byte_buf *dest);

/**
 * Read from the async stream until the buffer is full or EOF is reached.
 * This may perform multiple read_once() calls under the hood.
 * The read may complete synchronously, and may complete on another thread.
 * Returns aws_future<bool>, which on completion holds a bool indicating EOF or an error code.
 */
AWS_IO_API
struct aws_future_bool *aws_async_stream_read_to_fill(struct aws_async_stream *stream, struct aws_byte_buf *dest);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_IO_ASYNC_STREAM_H */

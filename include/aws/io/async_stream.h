/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_ASYNC_STREAM_H
#define AWS_IO_ASYNC_STREAM_H

/**
 * THIS IS AN EXPERIMENTAL AND UNSTABLE API
 * TODO: modify API to return byte-bufs, instead of filling in the provided byte-buf?
 *       this would avoid a copy in the use-cases we know of, but it's more complex
 * TODO: vtable acquire()/release()?
 * TODO: protect against simultaneous reads?
 */

#include <aws/io/io.h>

#include <aws/common/ref_count.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_async_input_stream;
struct aws_byte_buf;
struct aws_future_bool;
struct aws_input_stream;

struct aws_async_input_stream {
    const struct aws_async_input_stream_vtable *vtable;
    struct aws_allocator *alloc;
    struct aws_ref_count ref_count;
    void *impl;
};

struct aws_async_input_stream_vtable {
    void (*destroy)(struct aws_async_input_stream *stream);
    struct aws_future_bool *(*read)(struct aws_async_input_stream *stream, struct aws_byte_buf *dest);
};

AWS_EXTERN_C_BEGIN

/**
 * Initialize aws_async_input_stream "base class"
 */
AWS_IO_API
void aws_async_input_stream_init_base(
    struct aws_async_input_stream *stream,
    struct aws_allocator *alloc,
    const struct aws_async_input_stream_vtable *vtable,
    void *impl);

/**
 * Increment reference count.
 * You may pass in NULL (has no effect).
 * Returns whatever pointer was passed in.
 */
AWS_IO_API
struct aws_async_input_stream *aws_async_input_stream_acquire(struct aws_async_input_stream *stream);

/**
 * Decrement reference count.
 * You may pass in NULL (has no effect).
 * Always returns NULL.
 */
AWS_IO_API
struct aws_async_input_stream *aws_async_input_stream_release(struct aws_async_input_stream *stream);

/**
 * Read once from the async stream into the buffer.
 * The read completes when at least 1 byte is read, the buffer is full, or EOF is reached.
 * Depending on implementation, the read could complete at any time.
 * It may complete synchronously. It may complete on another thread.
 * Returns a future, which will contain an error code if something went wrong,
 * or a result bool indicating whether EOF has been reached.
 */
AWS_IO_API
struct aws_future_bool *aws_async_input_stream_read(struct aws_async_input_stream *stream, struct aws_byte_buf *dest);

/**
 * Read repeatedly from the async stream until the buffer is full, or EOF is reached.
 * Depending on implementation, this could complete at any time.
 * It may complete synchronously. It may complete on another thread.
 * Returns a future, which will contain an error code if something went wrong,
 * or a result bool indicating whether EOF has been reached.
 */
AWS_IO_API
struct aws_future_bool *aws_async_input_stream_read_to_fill(
    struct aws_async_input_stream *stream,
    struct aws_byte_buf *dest);

/**
 * Create a new async stream, which wraps a synchronous aws_input_stream.
 * Async read calls will always complete synchronously, since the
 * underlying source is synchronous.
 * The new stream acquires a reference to the `source` stream.
 * This function cannot fail.
 */
AWS_IO_API
struct aws_async_input_stream *aws_async_input_stream_new_from_synchronous(
    struct aws_allocator *alloc,
    struct aws_input_stream *source);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_IO_ASYNC_STREAM_H */

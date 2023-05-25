/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/async_stream.h>

#include <aws/common/byte_buf.h>
#include <aws/io/future.h>

void aws_async_stream_init_base(
    struct aws_async_stream *stream,
    struct aws_allocator *alloc,
    const struct aws_async_stream_vtable *vtable,
    void *impl) {

    AWS_ZERO_STRUCT(*stream);
    stream->alloc = alloc;
    stream->vtable = vtable;
    stream->impl = impl;
    aws_ref_count_init(&stream->ref_count, stream, (aws_simple_completion_callback *)vtable->destroy);
}

struct aws_async_stream *aws_async_stream_acquire(struct aws_async_stream *stream) {
    if (stream != NULL) {
        aws_ref_count_acquire(&stream->ref_count);
    }
    return stream;
}

struct aws_async_stream *aws_async_stream_release(struct aws_async_stream *stream) {
    if (stream) {
        aws_ref_count_release(&stream->ref_count);
    }
    return NULL;
}

struct aws_future_bool *aws_async_stream_read(struct aws_async_stream *stream, struct aws_byte_buf *dest) {
    /* Deal with this edge case here, instead of relying on every implementation to do it right. */
    if (dest->len == dest->capacity) {
        struct aws_future_bool *future = aws_future_bool_new(stream->alloc);
        aws_future_bool_set_error(future, AWS_ERROR_SHORT_BUFFER);
        return future;
    }

    return stream->vtable->read(stream, dest);
}

/* Data to perform the aws_async_stream_read_to_fill() job */
struct aws_async_stream_fill_job {
    struct aws_allocator *alloc;
    struct aws_async_stream *stream;
    struct aws_byte_buf *dest;
    /* Future for each read() step */
    struct aws_future_bool *read1_future;
    /* Future to set when this job completes */
    struct aws_future_bool *my_future;
};

static void s_async_stream_fill_job_complete(struct aws_async_stream_fill_job *job, bool eof, int error_code) {
    if (error_code) {
        aws_future_bool_set_error(job->my_future, error_code);
    } else {
        aws_future_bool_set_result(job->my_future, eof);
    }
    aws_future_bool_release(job->my_future);
    aws_async_stream_release(job->stream);
    aws_mem_release(job->alloc, job);
}

/* Call read() in a loop.
 * It would be simpler to set a completion callback for each read() call,
 * but this risks our call stack growing large if there are many small, synchronous, reads.
 * So be complicated and loop until a read() ) call is actually async,
 * and only then set the completion callback (which is this same function, where we resume looping). */
static void s_async_stream_fill_job_loop(void *user_data) {
    struct aws_async_stream_fill_job *job = user_data;

    while (true) {
        /* Process read1_future from previous iteration of loop.
         * It's NULL the first time the job ever enters the loop.
         * But it's set in subsequent runs of the loop, and when this is a read1_future completion callback. */
        if (job->read1_future) {
            if (aws_future_bool_register_callback_if_not_done(job->read1_future, s_async_stream_fill_job_loop, job)) {
                /* not done, we'll resume this loop when callback fires */
                return;
            }

            /* read1_future is done */
            int error_code = aws_future_bool_get_error(job->read1_future);
            bool eof = error_code ? false : aws_future_bool_get_result(job->read1_future);
            bool reached_capacity = job->dest->len == job->dest->capacity;
            job->read1_future = aws_future_bool_release(job->read1_future); /* release and NULL */

            if (error_code || eof || reached_capacity) {
                /* job complete! */
                s_async_stream_fill_job_complete(job, eof, error_code);
                return;
            }
        }

        /* Kick off a read, which may or may not complete async */
        job->read1_future = aws_async_stream_read(job->stream, job->dest);
    }
}

struct aws_future_bool *aws_async_stream_read_to_fill(struct aws_async_stream *stream, struct aws_byte_buf *dest) {

    struct aws_future_bool *future = aws_future_bool_new(stream->alloc);

    /* Deal with this edge case here, instead of relying on every implementation to do it right. */
    if (dest->len == dest->capacity) {
        aws_future_bool_set_error(future, AWS_ERROR_SHORT_BUFFER);
        return future;
    }

    struct aws_async_stream_fill_job *job = aws_mem_calloc(stream->alloc, 1, sizeof(struct aws_async_stream_fill_job));
    job->alloc = stream->alloc;
    job->stream = aws_async_stream_acquire(stream);
    job->dest = dest;
    job->my_future = aws_future_bool_acquire(future);

    /* Kick off work  */
    s_async_stream_fill_job_loop(job);

    return future;
}

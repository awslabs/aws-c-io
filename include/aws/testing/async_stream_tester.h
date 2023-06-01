#ifndef AWS_TESTING_ASYNC_STREAM_TESTER_H
#define AWS_TESTING_ASYNC_STREAM_TESTER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/async_stream.h>

#include <aws/common/byte_buf.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/io/future.h>

/**
 * Use aws_async_input_stream_tester to test edge cases in systems that take async streams.
 * You can customize its behavior (e.g. fail on 3rd read, always complete async, always complete synchronously, etc)
 */

struct aws_async_input_stream_tester_options {
    /* bytes to be streamed
     * the stream copies these to its own internal buffer */
    struct aws_byte_cursor source_bytes;

    enum aws_async_input_stream_tester_completion_strategy {
        /* the tester has its own thread, and reads always complete from there */
        AWS_AIST_READ_COMPLETES_ON_ANOTHER_THREAD,
        /* reads complete before read() even returns */
        AWS_AIST_READ_COMPLETES_IMMEDIATELY,
        /* sometimes reads complete immediately, sometimes they complete on another thread */
        AWS_AIST_READ_COMPLETES_ON_RANDOM_THREAD,
    } completion_strategy;

    /* if non-zero, a read will take at least this long to complete */
    uint64_t read_duration_ns;

    /* if non-zero, read at most N bytes per read() */
    size_t max_bytes_per_read;

    /* If false, EOF is reported by the read() which produces the last few bytes.
     * If true, EOF isn't reported until there's one more read(), producing zero bytes.
     * This emulates an underlying stream that reports EOF by reading 0 bytes */
    bool eof_requires_extra_read;

    /* if non-zero, fail the Nth time read() is called, raising `fail_with_error_code` */
    size_t fail_on_nth_read;

    /* error-code to raise if failing on purpose */
    int fail_with_error_code;
};

struct aws_async_input_stream_tester {
    struct aws_async_input_stream base;
    struct aws_allocator *alloc;
    struct aws_byte_buf source_buf;
    struct aws_async_input_stream_tester_options options;

    struct aws_thread thread;
    struct {
        struct aws_mutex lock;
        struct aws_condition_variable cvar;

        /* when thread should perform a read, these are set */
        struct aws_byte_buf *read_dest;
        struct aws_future_bool *read_future;

        /* if true, thread should shut down */
        bool do_shutdown;
    } synced_data;

    struct aws_byte_cursor current_cursor;
    size_t read_count;
    struct aws_atomic_var num_outstanding_reads;
};

void s_async_input_stream_tester_do_actual_read(
    struct aws_async_input_stream_tester *impl,
    struct aws_byte_buf *dest,
    struct aws_future_bool *read_future) {

    int error_code = 0;
    bool eof = false;

    impl->read_count++;

    /* delay, if that's how we're configured */
    if (impl->options.read_duration_ns != 0) {
        aws_thread_current_sleep(impl->options.read_duration_ns);
    }

    /* raise error, if that's how we're configured */
    if (impl->read_count == impl->options.fail_on_nth_read) {
        AWS_FATAL_ASSERT(impl->options.fail_with_error_code != 0);
        error_code = impl->options.fail_with_error_code;
        goto done;
    }

    /* figure out how much to read */
    size_t actually_read = dest->capacity - dest->len;
    actually_read = aws_min_size(actually_read, impl->current_cursor.len);
    if (impl->options.max_bytes_per_read != 0) {
        actually_read = aws_min_size(actually_read, impl->options.max_bytes_per_read);
    }

    /* copy bytes */
    aws_byte_buf_write(dest, impl->current_cursor.ptr, actually_read);
    aws_byte_cursor_advance(&impl->current_cursor, actually_read);

    /* set EOF. If configured with eof_requires_extra_read,
     * don't set it until there's a final read() that gets zero bytes */
    if (impl->options.eof_requires_extra_read) {
        eof = (actually_read == 0);
    } else {
        eof = (impl->current_cursor.len == 0);
    }

done:
    aws_atomic_fetch_sub(&impl->num_outstanding_reads, 1);

    if (error_code != 0) {
        aws_future_bool_set_error(read_future, error_code);
    } else {
        aws_future_bool_set_result(read_future, eof);
    }

    aws_future_bool_release(read_future);
}

AWS_STATIC_IMPL
struct aws_future_bool *s_async_input_stream_tester_read(
    struct aws_async_input_stream *stream,
    struct aws_byte_buf *dest) {

    struct aws_async_input_stream_tester *impl = stream->impl;

    size_t prev_outstanding_reads = aws_atomic_fetch_add(&impl->num_outstanding_reads, 1);
    AWS_FATAL_ASSERT(prev_outstanding_reads == 0 && "Overlapping read() calls are forbidden");

    struct aws_future_bool *read_future = aws_future_bool_new(stream->alloc);

    bool do_on_thread = false;
    switch (impl->options.completion_strategy) {
        case AWS_AIST_READ_COMPLETES_ON_ANOTHER_THREAD:
            do_on_thread = true;
            break;
        case AWS_AIST_READ_COMPLETES_ON_RANDOM_THREAD:
            do_on_thread = (rand() % 2 == 0);
            break;
        case AWS_AIST_READ_COMPLETES_IMMEDIATELY:
            do_on_thread = false;
            break;
    }

    if (do_on_thread) {
        /* BEGIN CRITICAL SECTION */
        aws_mutex_lock(&impl->synced_data.lock);
        impl->synced_data.read_dest = dest;
        impl->synced_data.read_future = aws_future_bool_acquire(read_future);
        AWS_FATAL_ASSERT(aws_condition_variable_notify_all(&impl->synced_data.cvar) == AWS_OP_SUCCESS);
        aws_mutex_unlock(&impl->synced_data.lock);
        /* END CRITICAL SECTION */
    } else {
        /* acquire additional refcount on future, since we call release once it's complete */
        aws_future_bool_acquire(read_future);
        s_async_input_stream_tester_do_actual_read(impl, dest, read_future);
    }

    return read_future;
}

AWS_STATIC_IMPL
void s_async_input_stream_tester_do_actual_destroy(struct aws_async_input_stream_tester *impl) {
    if (impl->options.completion_strategy != AWS_AIST_READ_COMPLETES_IMMEDIATELY) {
        aws_condition_variable_clean_up(&impl->synced_data.cvar);
        aws_mutex_clean_up(&impl->synced_data.lock);
    }

    aws_byte_buf_clean_up(&impl->source_buf);
    aws_mem_release(impl->base.alloc, impl);
}

/* refcount has reached zero */
AWS_STATIC_IMPL
void s_async_input_stream_tester_destroy(struct aws_async_input_stream *async_stream) {
    struct aws_async_input_stream_tester *impl = async_stream->impl;

    if (impl->options.completion_strategy == AWS_AIST_READ_COMPLETES_IMMEDIATELY) {
        s_async_input_stream_tester_do_actual_destroy(impl);
    } else {
        /* signal thread to finish cleaning things up */

        /* BEGIN CRITICAL SECTION */
        aws_mutex_lock(&impl->synced_data.lock);
        impl->synced_data.do_shutdown = true;
        AWS_FATAL_ASSERT(aws_condition_variable_notify_all(&impl->synced_data.cvar) == AWS_OP_SUCCESS);
        aws_mutex_unlock(&impl->synced_data.lock);
        /* END CRITICAL SECTION */
    }
}

AWS_STATIC_IMPL
bool s_async_input_stream_tester_thread_pred(void *arg) {
    struct aws_async_input_stream_tester *impl = arg;
    return impl->synced_data.do_shutdown || (impl->synced_data.read_dest != NULL);
}

AWS_STATIC_IMPL
void s_async_input_stream_tester_thread(void *arg) {
    struct aws_async_input_stream_tester *impl = arg;
    bool do_shutdown = false;
    struct aws_byte_buf *read_dest = NULL;
    struct aws_future_bool *read_future = NULL;
    while (!do_shutdown) {
        /* BEGIN CRITICAL SECTION */
        aws_mutex_lock(&impl->synced_data.lock);
        AWS_FATAL_ASSERT(
            aws_condition_variable_wait_pred(
                &impl->synced_data.cvar, &impl->synced_data.lock, s_async_input_stream_tester_thread_pred, impl) ==
            AWS_OP_SUCCESS);

        /* acquire work */
        do_shutdown = impl->synced_data.do_shutdown;
        read_dest = impl->synced_data.read_dest;
        impl->synced_data.read_dest = NULL;
        read_future = impl->synced_data.read_future;
        impl->synced_data.read_future = NULL;

        aws_mutex_unlock(&impl->synced_data.lock);
        /* END CRITICAL SECTION */

        if (read_dest != NULL) {
            s_async_input_stream_tester_do_actual_read(impl, read_dest, read_future);
        }
    }

    /* thread has shut down, finish destruction */
    s_async_input_stream_tester_do_actual_destroy(impl);
}

static struct aws_async_input_stream_vtable s_async_input_stream_tester_vtable = {
    .destroy = s_async_input_stream_tester_destroy,
    .read = s_async_input_stream_tester_read,
};

AWS_STATIC_IMPL
struct aws_async_input_stream *aws_async_input_stream_new_tester(
    struct aws_allocator *alloc,
    const struct aws_async_input_stream_tester_options *options) {

    struct aws_async_input_stream_tester *impl = aws_mem_calloc(alloc, 1, sizeof(struct aws_async_input_stream_tester));
    aws_async_input_stream_init_base(&impl->base, alloc, &s_async_input_stream_tester_vtable, impl);

    impl->options = *options;
    aws_byte_buf_init_copy_from_cursor(&impl->source_buf, alloc, options->source_bytes);
    impl->current_cursor = aws_byte_cursor_from_buf(&impl->source_buf);

    aws_atomic_init_int(&impl->num_outstanding_reads, 0);

    if (options->completion_strategy != AWS_AIST_READ_COMPLETES_IMMEDIATELY) {
        aws_mutex_init(&impl->synced_data.lock);
        aws_condition_variable_init(&impl->synced_data.cvar);

        AWS_FATAL_ASSERT(aws_thread_init(&impl->thread, alloc) == AWS_OP_SUCCESS);
        struct aws_thread_options thread_options = *aws_default_thread_options();
        thread_options.name = aws_byte_cursor_from_c_str("AsyncStream");
        thread_options.join_strategy = AWS_TJS_MANAGED;

        AWS_FATAL_ASSERT(
            aws_thread_launch(&impl->thread, s_async_input_stream_tester_thread, impl, &thread_options) ==
            AWS_OP_SUCCESS);
    }

    return &impl->base;
}

#endif /* AWS_TESTING_ASYNC_STREAM_TESTER_H */

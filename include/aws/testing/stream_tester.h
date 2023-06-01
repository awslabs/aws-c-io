#ifndef AWS_TESTING_STREAM_TESTER_H
#define AWS_TESTING_STREAM_TESTER_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/stream.h>

/**
 * Use aws_input_stream tester to test edge cases in systems that take input streams.
 * You can make it behave in specific weird ways (e.g. fail on 3rd read).
 */

struct aws_input_stream_tester_options {
    /* bytes to be streamed
     * the stream copies these to its own internal buffer */
    struct aws_byte_cursor source_bytes;

    /* if non-zero, read at most N bytes per read() */
    size_t max_bytes_per_read;

    /* if non-zero, read 0 bytes the Nth time read() is called */
    size_t read_zero_bytes_on_nth_read;

    /* if non-zero, fail the Nth time read() is called, raising `fail_with_error_code` */
    size_t fail_on_nth_read;

    /* error-code to raise if failing on purpose */
    int fail_with_error_code;
};

struct aws_input_stream_tester {
    struct aws_input_stream base;
    struct aws_allocator *alloc;
    struct aws_byte_buf source_buf;
    struct aws_input_stream_tester_options options;

    /* mutable state */
    struct aws_byte_cursor current_cursor;
    size_t read_count;
};

/* This is 100% copied from s_aws_input_stream_byte_cursor_seek() */
AWS_STATIC_IMPL
int s_input_stream_tester_seek(struct aws_input_stream *stream, int64_t offset, enum aws_stream_seek_basis basis) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);

    uint64_t final_offset = 0;

    switch (basis) {
        case AWS_SSB_BEGIN:
            /*
             * (uint64_t)offset -- safe by virtue of the earlier is-negative check
             * (uint64_t)impl->source_buf.len -- safe via assumption 1
             */
            if (offset < 0 || (uint64_t)offset > (uint64_t)impl->source_buf.len) {
                return aws_raise_error(AWS_IO_STREAM_INVALID_SEEK_POSITION);
            }

            /* safe because negative offsets were turned into an error */
            final_offset = (uint64_t)offset;
            break;

        case AWS_SSB_END:
            /*
             * -offset -- safe as long offset is not INT64_MIN which was previously checked
             * (uint64_t)(-offset) -- safe because (-offset) is positive (and < INT64_MAX < UINT64_MAX)
             */
            if (offset > 0 || offset == INT64_MIN || (uint64_t)(-offset) > (uint64_t)impl->source_buf.len) {
                return aws_raise_error(AWS_IO_STREAM_INVALID_SEEK_POSITION);
            }

            /* cases that would make this unsafe became errors with previous conditional */
            final_offset = (uint64_t)impl->source_buf.len - (uint64_t)(-offset);
            break;

        default:
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* true because we already validated against (impl->source_buf.len) which is <= SIZE_MAX */
    AWS_ASSERT(final_offset <= SIZE_MAX);

    /* safe via previous assert */
    size_t final_offset_sz = (size_t)final_offset;

    /* sanity */
    AWS_ASSERT(final_offset_sz <= impl->source_buf.len);

    /* reset current_cursor to new position */
    impl->current_cursor = aws_byte_cursor_from_buf(&impl->source_buf);
    impl->current_cursor.ptr += final_offset_sz;
    impl->current_cursor.len -= final_offset_sz;

    return AWS_OP_SUCCESS;
}

AWS_STATIC_IMPL
int s_input_stream_tester_read(struct aws_input_stream *stream, struct aws_byte_buf *dest) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);

    impl->read_count++;
    if (impl->read_count == impl->options.fail_on_nth_read) {
        AWS_FATAL_ASSERT(impl->options.fail_with_error_code != 0);
        return aws_raise_error(impl->options.fail_with_error_code);
    }

    if (impl->read_count == impl->options.read_zero_bytes_on_nth_read) {
        return AWS_OP_SUCCESS;
    }

    size_t actually_read = dest->capacity - dest->len;
    actually_read = aws_min_size(actually_read, impl->current_cursor.len);
    if (impl->options.max_bytes_per_read != 0) {
        actually_read = aws_min_size(actually_read, impl->options.max_bytes_per_read);
    }

    aws_byte_buf_write(dest, impl->current_cursor.ptr, actually_read);
    aws_byte_cursor_advance(&impl->current_cursor, actually_read);

    return AWS_OP_SUCCESS;
}

AWS_STATIC_IMPL
int s_input_stream_tester_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);
    status->is_valid = true;
    status->is_end_of_stream = impl->current_cursor.len == 0;
    return AWS_OP_SUCCESS;
}

AWS_STATIC_IMPL
int s_input_stream_tester_get_length(struct aws_input_stream *stream, int64_t *out_length) {
    struct aws_input_stream_tester *impl = AWS_CONTAINER_OF(stream, struct aws_input_stream_tester, base);
    *out_length = (int64_t)impl->source_buf.len;
    return AWS_OP_SUCCESS;
}

static struct aws_input_stream_vtable s_input_stream_tester_vtable = {
    .seek = s_input_stream_tester_seek,
    .read = s_input_stream_tester_read,
    .get_status = s_input_stream_tester_get_status,
    .get_length = s_input_stream_tester_get_length,
};

AWS_STATIC_IMPL
void s_input_stream_tester_destroy(void *user_data) {
    struct aws_input_stream_tester *impl = user_data;
    aws_byte_buf_clean_up(&impl->source_buf);
    aws_mem_release(impl->alloc, impl);
}

AWS_STATIC_IMPL
struct aws_input_stream *aws_input_stream_new_tester(
    struct aws_allocator *alloc,
    const struct aws_input_stream_tester_options *options) {

    struct aws_input_stream_tester *impl = aws_mem_calloc(alloc, 1, sizeof(struct aws_input_stream_tester));
    impl->base.impl = impl;
    impl->base.vtable = &s_input_stream_tester_vtable;
    aws_ref_count_init(&impl->base.ref_count, impl, s_input_stream_tester_destroy);
    impl->alloc = alloc;
    aws_byte_buf_init_copy_from_cursor(&impl->source_buf, alloc, options->source_bytes);
    impl->current_cursor = aws_byte_cursor_from_buf(&impl->source_buf);
    impl->options = *options;

    return &impl->base;
}

#endif /* AWS_TESTING_STREAM_TESTER_H */

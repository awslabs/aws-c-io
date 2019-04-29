/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/io/stream.h>

#include <aws/io/file_utils.h>

int aws_input_stream_seek(struct aws_input_stream *stream, aws_off_t offset, enum aws_stream_seek_basis basis) {
    assert(stream && stream->vtable && stream->vtable->seek);

    return stream->vtable->seek(stream, offset, basis);
}

int aws_input_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest, size_t *amount_read) {
    assert(stream && stream->vtable && stream->vtable->read);

    return stream->vtable->read(stream, dest, amount_read);
}

int aws_input_stream_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    assert(stream && stream->vtable && stream->vtable->get_status);

    return stream->vtable->get_status(stream, status);
}

int aws_input_stream_get_length(struct aws_input_stream *stream, size_t *out_length) {
    assert(stream && stream->vtable && stream->vtable->get_length);

    return stream->vtable->get_length(stream, out_length);
}

void aws_input_stream_destroy(struct aws_input_stream *stream) {
    if (stream != NULL) {
        assert(stream->vtable && stream->vtable->clean_up);

        stream->vtable->clean_up(stream);

        aws_mem_release(stream->allocator, stream);
    }
}

/*
 * cursor stream implementation
 */

struct aws_input_stream_byte_cursor_impl {
    struct aws_byte_cursor original_cursor;
    struct aws_byte_cursor current_cursor;
};

/*
 * This is an ugly function that, in the absence of better guidance, is designed to handle all possible combinations of
 *  aws_off_t (int32_t, int64_t) x all possible combinations of size_t (uint32_t, uint64_t).  Whether the anomalous
 * combination of int64_t vs. uint32_t is even possible on any real platform is unknown.  If size_t ever exceeds 64 bits
 * this function will fail badly.
 *
 *  Safety and invariant assumptions are sprinkled via comments.  The overall strategy is to cast up to 64 bits and
 * perform all arithmetic there, being careful with signed vs. unsigned to prevent bad operations.
 *
 *  Assumption #1: aws_off_t resolves to a signed integer 64 bits or smaller
 *  Assumption #2: size_t resolves to an unsigned integer 64 bits or smaller
 */
static int s_aws_input_stream_byte_cursor_seek(
    struct aws_input_stream *stream,
    aws_off_t offset,
    enum aws_stream_seek_basis basis) {
    struct aws_input_stream_byte_cursor_impl *impl = stream->impl;

    uint64_t final_offset = 0;
    int64_t checked_offset = offset; /* safe by assumption 1 */

    switch (basis) {
        case AWS_SSB_BEGIN:
            /*
             * (uint64_t)checked_offset -- safe by virtue of the earlier is-negative check + Assumption 1
             * (uint64_t)impl->original_cursor.len -- safe via assumption 2
             */
            if (checked_offset < 0 || (uint64_t)checked_offset > (uint64_t)impl->original_cursor.len) {
                return aws_raise_error(AWS_IO_STREAM_INVALID_SEEK_POSITION);
            }

            /* safe because negative offsets were turned into an error */
            final_offset = (uint64_t)checked_offset;
            break;

        case AWS_SSB_END:
            /*
             * -checked_offset -- safe as long checked_offset is not INT64_MIN which was previously checked
             * (uint64_t)(-checked_offset) -- safe because (-checked_offset) is positive (and < INT64_MAX < UINT64_MAX)
             */
            if (checked_offset > 0 || checked_offset == INT64_MIN ||
                (uint64_t)(-checked_offset) > (uint64_t)impl->original_cursor.len) {
                return aws_raise_error(AWS_IO_STREAM_INVALID_SEEK_POSITION);
            }

            /* cases that would make this unsafe became errors with previous conditional */
            final_offset = (uint64_t)impl->original_cursor.len - (uint64_t)(-checked_offset);
            break;
    }

    /* true because we already validated against (impl->original_cursor.len) which is <= SIZE_MAX */
    assert(final_offset <= SIZE_MAX);

    impl->current_cursor = impl->original_cursor;

    /* (size_t) final_offset - safe via previous assert's reasoning */
    aws_byte_cursor_advance(&impl->current_cursor, (size_t)final_offset);

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_byte_cursor_read(
    struct aws_input_stream *stream,
    struct aws_byte_buf *dest,
    size_t *amount_read) {
    struct aws_input_stream_byte_cursor_impl *impl = stream->impl;

    *amount_read = 0;

    size_t actually_read = dest->capacity - dest->len;
    if (actually_read > impl->current_cursor.len) {
        actually_read = impl->current_cursor.len;
    }

    if (!aws_byte_buf_write(dest, impl->current_cursor.ptr, actually_read)) {
        return AWS_OP_ERR;
    }

    aws_byte_cursor_advance(&impl->current_cursor, actually_read);

    *amount_read = actually_read;

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_byte_cursor_get_status(
    struct aws_input_stream *stream,
    struct aws_stream_status *status) {
    struct aws_input_stream_byte_cursor_impl *impl = stream->impl;

    status->is_end_of_stream = impl->current_cursor.len == 0;
    status->is_valid = true;

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_byte_cursor_get_length(struct aws_input_stream *stream, size_t *out_length) {
    struct aws_input_stream_byte_cursor_impl *impl = stream->impl;

    *out_length = impl->original_cursor.len;

    return AWS_OP_SUCCESS;
}

static void s_aws_input_stream_byte_cursor_clean_up(struct aws_input_stream *stream) {
    struct aws_input_stream_byte_cursor_impl *impl = stream->impl;

    aws_mem_release(stream->allocator, impl);
}

static struct aws_input_stream_vtable s_aws_input_stream_byte_cursor_vtable = {
    .seek = s_aws_input_stream_byte_cursor_seek,
    .read = s_aws_input_stream_byte_cursor_read,
    .get_status = s_aws_input_stream_byte_cursor_get_status,
    .get_length = s_aws_input_stream_byte_cursor_get_length,
    .clean_up = s_aws_input_stream_byte_cursor_clean_up};

struct aws_input_stream *aws_input_stream_new_from_cursor(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *cursor) {
    struct aws_input_stream *input_stream = aws_mem_acquire(allocator, sizeof(struct aws_input_stream));
    if (input_stream == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*input_stream);

    input_stream->allocator = allocator;
    input_stream->vtable = &s_aws_input_stream_byte_cursor_vtable;

    struct aws_input_stream_byte_cursor_impl *impl =
        aws_mem_acquire(allocator, sizeof(struct aws_input_stream_byte_cursor_impl));
    if (impl == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*impl);
    impl->original_cursor = *cursor;
    impl->current_cursor = *cursor;

    input_stream->impl = impl;

    return input_stream;

on_error:

    aws_input_stream_destroy(input_stream);

    return NULL;
}

/*
 * file-based input stream
 */
struct aws_input_stream_file_impl {
    FILE *file;
    bool close_on_clean_up;
};

static int s_aws_input_stream_file_seek(
    struct aws_input_stream *stream,
    aws_off_t offset,
    enum aws_stream_seek_basis basis) {
    struct aws_input_stream_file_impl *impl = stream->impl;

    int whence = (basis == AWS_SSB_BEGIN) ? SEEK_SET : SEEK_END;
    if (aws_fseek(impl->file, offset, whence)) {
        return aws_raise_error(aws_io_translate_and_raise_io_error(aws_last_error()));
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_file_read(
    struct aws_input_stream *stream,
    struct aws_byte_buf *dest,
    size_t *amount_read) {
    struct aws_input_stream_file_impl *impl = stream->impl;

    *amount_read = 0;

    size_t max_read = dest->capacity - dest->len;
    size_t actually_read = fread(dest->buffer + dest->len, 1, max_read, impl->file);
    if (actually_read == 0) {
        if (ferror(impl->file)) {
            return AWS_OP_ERR;
        }
    }

    dest->len += actually_read;

    *amount_read = actually_read;

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_file_get_status(struct aws_input_stream *stream, struct aws_stream_status *status) {
    struct aws_input_stream_file_impl *impl = stream->impl;

    status->is_end_of_stream = feof(impl->file) != 0;
    status->is_valid = ferror(impl->file) == 0;

    return AWS_OP_SUCCESS;
}

static int s_aws_input_stream_file_get_length(struct aws_input_stream *stream, size_t *length) {
    struct aws_input_stream_file_impl *impl = stream->impl;

    return aws_file_get_length(impl->file, length);
}

static void s_aws_input_stream_file_clean_up(struct aws_input_stream *stream) {
    struct aws_input_stream_file_impl *impl = stream->impl;

    if (impl->close_on_clean_up && impl->file) {
        fclose(impl->file);
    }

    aws_mem_release(stream->allocator, impl);
}

static struct aws_input_stream_vtable s_aws_input_stream_file_vtable = {
    .seek = s_aws_input_stream_file_seek,
    .read = s_aws_input_stream_file_read,
    .get_status = s_aws_input_stream_file_get_status,
    .get_length = s_aws_input_stream_file_get_length,
    .clean_up = s_aws_input_stream_file_clean_up};

struct aws_input_stream *aws_input_stream_new_from_file(struct aws_allocator *allocator, const char *file_name) {
    struct aws_input_stream *input_stream = aws_mem_acquire(allocator, sizeof(struct aws_input_stream));
    if (input_stream == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*input_stream);

    input_stream->allocator = allocator;
    input_stream->vtable = &s_aws_input_stream_file_vtable;

    struct aws_input_stream_file_impl *impl = aws_mem_acquire(allocator, sizeof(struct aws_input_stream_file_impl));
    if (impl == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*impl);
    impl->file = fopen(file_name, "r");
    if (impl->file == NULL) {
        goto on_error;
    }

    impl->close_on_clean_up = true;

    input_stream->impl = impl;

    return input_stream;

on_error:

    aws_input_stream_destroy(input_stream);

    return NULL;
}

struct aws_input_stream *aws_input_stream_new_from_open_file(struct aws_allocator *allocator, FILE *file) {
    struct aws_input_stream *input_stream = aws_mem_acquire(allocator, sizeof(struct aws_input_stream));
    if (input_stream == NULL) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*input_stream);

    input_stream->allocator = allocator;
    input_stream->vtable = &s_aws_input_stream_file_vtable;

    struct aws_input_stream_file_impl *impl = aws_mem_acquire(allocator, sizeof(struct aws_input_stream_file_impl));
    if (impl == NULL) {
        goto on_error;
    }

    AWS_ZERO_STRUCT(*impl);
    impl->file = file;
    impl->close_on_clean_up = false;

    input_stream->impl = impl;

    return input_stream;

on_error:

    aws_input_stream_destroy(input_stream);

    return NULL;
}

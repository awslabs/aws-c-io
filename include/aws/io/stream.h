#ifndef AWS_IO_STREAM_H
#define AWS_IO_STREAM_H

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

#include <aws/io/io.h>

struct aws_input_stream;
struct aws_byte_buf;

/*
 * For seek calls, where in the stream to seek from.
 * CUR support can come later
 * Intentionally mirror libc constants
 */
enum aws_stream_seek_basis { AWS_SSB_BEGIN = 0, AWS_SSB_END = 2 };

struct aws_stream_status {
    bool is_end_of_stream;
    bool is_valid;
};

typedef int(aws_input_stream_seek_fn)(struct aws_input_stream *stream, aws_off_t offset, enum aws_stream_seek_basis);
typedef int(aws_input_stream_read_fn)(struct aws_input_stream *stream, struct aws_byte_buf *dest, size_t *amount_read);
typedef int(aws_input_stream_get_status_fn)(struct aws_input_stream *stream, struct aws_stream_status *status);
typedef int(aws_input_stream_get_length_fn)(struct aws_input_stream *stream, size_t *out_length);
typedef void(aws_input_stream_clean_up_fn)(struct aws_input_stream *stream);

struct aws_input_stream_vtable {
    aws_input_stream_seek_fn *seek;
    aws_input_stream_read_fn *read;
    aws_input_stream_get_status_fn *get_status;
    aws_input_stream_get_length_fn *get_length;
    aws_input_stream_clean_up_fn *clean_up;
};

struct aws_input_stream {
    struct aws_allocator *allocator;
    void *impl;
    struct aws_input_stream_vtable *vtable;
};

AWS_EXTERN_C_BEGIN

/*
 * Seek to a position within a stream; analagous to fseek() and its relatives
 */
int aws_input_stream_seek(struct aws_input_stream *stream, aws_off_t offset, enum aws_stream_seek_basis);

/*
 * Read data from a stream.  If data is available, will read up to the (capacity - len) open bytes
 * in the destination buffer.
 */
int aws_input_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest, size_t *amount_read);

/*
 * Queries miscellaneous properties of the stream
 */
int aws_input_stream_get_status(struct aws_input_stream *stream, struct aws_stream_status *status);

/*
 * Returns the total stream length, if able, regardless of current stream position.  Under certain conditions,
 * a valid stream may return an error instead when there is not a good answer (socket stream, for example).
 *
 */
int aws_input_stream_get_length(struct aws_input_stream *stream, size_t *out_length);

/*
 * Tears down the stream
 */
void aws_input_stream_destroy(struct aws_input_stream *stream);

/*
 * Creates a stream that operates on a range of bytes
 */
struct aws_input_stream *aws_input_stream_new_from_cursor(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *cursor);

/*
 * Creates a stream that operates on a (not-yet-opened) file.
 * Destruction closes the file.
 */
struct aws_input_stream *aws_input_stream_new_from_file(struct aws_allocator *allocator, const char *file_name);

/*
 * Creates an input stream that reads from an already opened file.
 * Destruction does not close the file.
 */
struct aws_input_stream *aws_input_stream_new_from_open_file(struct aws_allocator *allocator, FILE *file);

AWS_EXTERN_C_END

#endif /* AWS_IO_STREAM_H */

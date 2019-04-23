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

enum aws_stream_seek_basis {
    AWS_SSB_BEGIN = 0,
    AWS_SSB_END = 2
};

struct aws_input_stream;
struct aws_byte_buf;

typedef int (aws_input_stream_seek_fn)(struct aws_input_stream *stream, size_t offset, enum aws_stream_seek_basis);
typedef int (aws_input_stream_read_fn)(struct aws_input_stream *stream, struct aws_byte_buf *dest, size_t *amount_read);
typedef int (aws_input_stream_eof_fn)(struct aws_input_stream *stream, bool *is_eof);
typedef void (aws_input_stream_clean_up_fn)(struct aws_input_stream *stream);

struct aws_input_stream_vtable {
    aws_input_stream_seek_fn *seek;
    aws_input_stream_read_fn *read;
    aws_input_stream_eof_fn *eof;
    aws_input_stream_clean_up_fn *clean_up;
};

struct aws_input_stream {
    struct aws_allocator *allocator;
    struct aws_input_stream_vtable *vtable;
    void *impl;
};

AWS_EXTERN_C_BEGIN

int aws_input_stream_seek(struct aws_input_stream *stream, size_t offset, enum aws_stream_seek_basis);

int aws_input_stream_read(struct aws_input_stream *stream, struct aws_byte_buf *dest, size_t *amount_read);

int aws_input_stream_eof(struct aws_input_stream *stream, bool *is_eof);

void aws_input_stream_destroy(struct aws_input_stream *stream);

struct aws_input_stream *aws_input_stream_new_from_cursor(struct aws_allocator *allocator, const struct aws_byte_cursor *cursor);

struct aws_input_stream *aws_input_stream_new_from_file(struct aws_allocator *allocator, const char *file_name);

struct aws_input_stream *aws_input_stream_new_from_open_file(struct aws_allocator *allocator, FILE *file);

AWS_EXTERN_C_END

#endif /* AWS_IO_STREAM_H */

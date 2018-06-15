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

#include <aws/io/exports.h>

struct aws_byte_cursor;
struct aws_byte_buf;
struct aws_io_handle;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens a OS specific bidirectional pipe. The read direction is stored in read_handle. Write direction is stored in
 * write_handle. These are always non-blocking.
 */
AWS_IO_API int aws_pipe_open(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle);

/**
 * Closes pipe in both directions.
 */
AWS_IO_API int aws_pipe_close(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle);

/**
 * Closes pipe in a single direction.
 */
AWS_IO_API int aws_pipe_half_close(struct aws_io_handle *handle);


/**
 * Writes up to buf->len to the pipe. The amount successfully written will be stored in written. Errors, such as EAGAIN, EWOULDBLOCK
 * will be indicated by -1 return value, call aws_last_error() to get the specific error.
 */
AWS_IO_API int aws_pipe_write (struct aws_io_handle *handle, struct aws_byte_cursor *cursor, size_t *written);

/**
 * Reads up to buf->len from the pipe. The amount successfully read will be stored in amount_read. Errors, such as EAGAIN, EWOULDBLOCK
 * will be indicated by -1 return value, call aws_last_error() to get the specific error.
 */
AWS_IO_API int aws_pipe_read (struct aws_io_handle *handle, struct aws_byte_buf *buf, size_t *amount_read);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_PIPE_H */

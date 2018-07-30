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

struct aws_io_handle;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens a OS specific bidirectional pipe. The read direction is stored in read_handle. Write direction is stored in
 * write_handle. These are always non-blocking.
 */
AWS_IO_API
int aws_pipe_open(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle);

/**
 * Closes pipe in both directions.
 */
AWS_IO_API
int aws_pipe_close(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle);

/**
 * Closes pipe in a single direction.
 */
AWS_IO_API
int aws_pipe_half_close(struct aws_io_handle *handle);

/**
 * Writes data from `src` buffer to the pipe.
 * Up to `src_size` bytes will be written.
 * The amount successfully written will be stored in `num_bytes_written`.
 * This function never blocks. If a block would be required to write then
 * AWS_OP_ERR is returned and aws_last_error() code will be AWS_IO_WRITE_WOULD_BLOCK.
 */
AWS_IO_API
int aws_pipe_write(struct aws_io_handle *handle, const uint8_t *src, size_t src_size, size_t *num_bytes_written);

/**
 * Reads data from the pipe to the `dst` buffer.
 * Up to `dst_size` bytes will be read.
 * The number of bytes successfully read will be stored in `num_bytes_read`.
 * This function never blocks. If a block would be required to read then AWS_OP_ERR is
 * returned and aws_last_error() code will be AWS_IO_READ_WOULD_BLOCK.
 */
AWS_IO_API
int aws_pipe_read(struct aws_io_handle *handle, uint8_t *dst, size_t dst_size, size_t *num_bytes_read);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_PIPE_H */

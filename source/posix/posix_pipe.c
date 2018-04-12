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

#include <aws/io/io.h>
#include <aws/common/byte_buf.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int aws_pipe_open(struct aws_allocator *allocator, struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    int pipe_fds[2] = {0};

    if (pipe(pipe_fds)) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    int flags = fcntl(pipe_fds[0], F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(pipe_fds[0], F_SETFL, flags);
    flags = fcntl(pipe_fds[1], F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(pipe_fds[1], F_SETFL, flags);

    read_handle->handle = pipe_fds[0];
    read_handle->private_event_loop_data = NULL;

    write_handle->handle = pipe_fds[1];
    write_handle->private_event_loop_data = NULL;

    return AWS_OP_SUCCESS;
}

int aws_pipe_close(struct aws_allocator *allocator, struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    if (read_handle) {
        close(read_handle->handle);
    }

    if (write_handle) {
        close(write_handle->handle);
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_write (struct aws_io_handle *handle, const struct aws_byte_buf *buf, size_t *written) {

    ssize_t write_val = write(handle->handle, buf->buffer, buf->len);

    if (write_val > 0) {
        *written = (size_t)write_val;
        return AWS_OP_SUCCESS;
    }

    int error = errno;
    if (error == EAGAIN) {
        return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

int aws_pipe_read (struct aws_io_handle *handle, struct aws_byte_buf *buf, size_t *amount_read) {
    ssize_t read_val = read(handle->handle, buf->buffer, buf->len);

    if (read_val > 0) {
        *amount_read = (size_t)read_val;
        return AWS_OP_SUCCESS;
    }

    int error = errno;
    if (error == EAGAIN) {
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}


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

#ifdef __GLIBC__
#define __USE_GNU
#endif

/* TODO: move this detection to CMAKE and a config header */
#if !defined(COMPAT_MODE) && defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 9
#define HAVE_PIPE2 1
#else
#define HAVE_PIPE2 0
#endif

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>


int aws_pipe_open(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    int pipe_fds[2] = {0};

#if HAVE_PIPE2
    if (pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC)) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }
#else
    if (pipe(pipe_fds)) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    int flags = fcntl(pipe_fds[0], F_GETFL);
    flags |= O_NONBLOCK | O_CLOEXEC;
    fcntl(pipe_fds[0], F_SETFL, flags);
    flags = fcntl(pipe_fds[1], F_GETFL);
    flags |= O_NONBLOCK | O_CLOEXEC;
    fcntl(pipe_fds[1], F_SETFL, flags);
#endif
    read_handle->data.fd = pipe_fds[0];
    read_handle->additional_data = NULL;

    write_handle->data.fd = pipe_fds[1];
    write_handle->additional_data = NULL;

    return AWS_OP_SUCCESS;
}

int aws_pipe_close(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    assert(read_handle);
    assert(write_handle);

    close(read_handle->data.fd);
    read_handle->data.fd = -1;
    close(write_handle->data.fd);
    write_handle->data.fd = -1;

    return AWS_OP_SUCCESS;
}

int aws_pipe_half_close(struct aws_io_handle *handle) {
    assert(handle);
    close(handle->data.fd);
    handle->data.fd = -1;

    return AWS_OP_SUCCESS;
}

int aws_pipe_write (struct aws_io_handle *handle, const struct aws_byte_cursor *cursor, size_t *written) {

    ssize_t write_val = write(handle->data.fd, cursor->ptr, cursor->len);

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
    ssize_t read_val = read(handle->data, buf->buffer, buf->len);

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


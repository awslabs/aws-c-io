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

#include <aws/io/pipe.h>

#include <aws/io/io.h>

#ifdef __GLIBC__
#    define __USE_GNU
#endif

/* TODO: move this detection to CMAKE and a config header */
#if !defined(COMPAT_MODE) && defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 9
#    define HAVE_PIPE2 1
#else
#    define HAVE_PIPE2 0
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int aws_pipe_open(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    read_handle->data.fd = -1;
    read_handle->additional_data = NULL;
    write_handle->data.fd = -1;
    write_handle->additional_data = NULL;

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
    write_handle->data.fd = pipe_fds[1];

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

int aws_pipe_write(struct aws_io_handle *handle, const uint8_t *src, size_t src_size, size_t *written) {
    assert(handle);
    assert(src);

    if (written) {
        *written = 0;
    }

    ssize_t write_val = write(handle->data.fd, src, src_size);

    if (write_val >= 0) {
        if (written) {
            *written = (size_t)write_val;
        }
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

int aws_pipe_read(struct aws_io_handle *handle, uint8_t *dst, size_t dst_size, size_t *amount_read) {
    assert(handle);
    assert(dst);

    if (amount_read) {
        *amount_read = 0;
    }

    ssize_t read_val = read(handle->data.fd, dst, dst_size);

    if (read_val >= 0) {
        if (amount_read) {
            *amount_read = (size_t)read_val;
        }
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

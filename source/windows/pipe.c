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
#include <aws/io/pipe.h>

#define SUGGESTED_BUFFER_SIZE 4096

/* Translate Windows errors into aws_pipe errors */
static int raise_last_windows_error() {
    const DWORD err = GetLastError();
    switch (err) {
    case ERROR_INVALID_HANDLE:
        return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
    case ERROR_BROKEN_PIPE:
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    default:
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }
}

int aws_pipe_open(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    read_handle->handle.dataptr = INVALID_HANDLE_VALUE;
    write_handle->handle.dataptr = INVALID_HANDLE_VALUE;
    read_handle->additional_data = NULL;
    write_handle->additional_data = NULL;

    bool success = CreatePipe(
            &read_handle->handle.dataptr, /*read handle*/
            &write_handle->handle.dataptr, /*write handle*/
            NULL, /*NULL means default security attributes*/
            SUGGESTED_BUFFER_SIZE); /*suggested size, in bytes, for the pipe's buffer*/
    if (!success) {
        return raise_last_windows_error();
    }

    /* We use anonymous pipes (rather than named pipes) because they "require less overhead".
     * It's possible to set non-blocking IO on an anonymous pipe via SetNamedPipeHandleState() */
    DWORD read_mode = PIPE_NOWAIT | PIPE_READMODE_BYTE;
    success = SetNamedPipeHandleState(
            read_handle->handle.dataptr, /*pipe handle*/
            &read_mode, /*mode to set*/
            NULL, /*NULL if the collection count is not being set*/
            NULL); /*NULL if the collection count is not being set*/
    if (!success) {
        raise_last_windows_error();
        goto clean_up;
    }

    DWORD write_mode = PIPE_NOWAIT | PIPE_TYPE_BYTE;
    success = SetNamedPipeHandleState(
            write_handle->handle.dataptr, /*pipe handle*/
            &write_mode, /*mode to set*/
            NULL, /*NULL if the collection count is not being set*/
            NULL); /*NULL if the collection count is not being set*/
    if (!success) {
        raise_last_windows_error();
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    CloseHandle(read_handle->handle.dataptr);
    CloseHandle(write_handle->handle.dataptr);
    return AWS_OP_SUCCESS;
}

int aws_pipe_close(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    assert(read_handle && write_handle);

    int result = AWS_OP_SUCCESS;

    if (aws_pipe_half_close(read_handle)) {
        result = AWS_OP_ERR;
    }

    if (aws_pipe_half_close(write_handle)) {
        result = AWS_OP_ERR;
    }

    return result;
}

int aws_pipe_half_close(struct aws_io_handle *handle) {
    assert(handle);

    HANDLE h = handle->handle.dataptr;
    handle->handle.dataptr = INVALID_HANDLE_VALUE;

    if (!CloseHandle(h)) {
        return raise_last_windows_error();
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_write(struct aws_io_handle *handle, struct aws_byte_cursor *cursor, size_t *written) {
    assert(handle);
    assert(cursor);

    if (written) {
        *written = 0;
    }

    /* Return early if there's no work */
    if (cursor->len == 0) {
        return AWS_OP_SUCCESS;
    }

    /* HACK:
     * Despite what the documentation says:
     * https://msdn.microsoft.com/en-us/library/aa365605(v=vs.85).aspx
     *      When there is insufficient space in the pipe's buffer...
     *      with a nonblocking-wait handle, the write operation returns a nonzero value immediately...
     *      after writing as many bytes as the buffer holds.
     *
     * We want the behavior described above, but observed that WriteFile()
     * would not write ANY bytes unless it could write all the requested bytes.
     * We tried using named pipes and got the same results.
     *
     * Therefore, in a loop, attempt to write less and less bytes until we
     * write SOMETHING, or we give up.
     */
    const DWORD PARTIAL_WRITE_RETRY_MIN = 128; /*If we can't write this many bytes, give up*/
    const DWORD PARTIAL_WRITE_RETRY_RSHIFT = 2; /*If we can't write, decrease bytes_to_write by rshifting this much*/
    DWORD bytes_to_write = cursor->len > SUGGESTED_BUFFER_SIZE ? SUGGESTED_BUFFER_SIZE : (DWORD)cursor->len;
    DWORD bytes_written;
    while (true) {
        if (!WriteFile(handle->handle.dataptr, cursor->ptr, bytes_to_write, &bytes_written, NULL/*lpOverlapped*/)) {
            return raise_last_windows_error();
        }

        if (bytes_written > 0) {
            break;
        }

        if (bytes_to_write < PARTIAL_WRITE_RETRY_MIN) {
            return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
        }

        bytes_to_write = bytes_to_write >> PARTIAL_WRITE_RETRY_RSHIFT;
    }

    aws_byte_cursor_advance(cursor, (size_t)bytes_written);

    if (written) {
        *written = bytes_written;
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_read(struct aws_io_handle *handle, struct aws_byte_buf *buf, size_t *amount_read) {
    assert(handle);
    assert(buf);

    if (amount_read) {
        *amount_read = 0;
    }

    size_t remaining_capacity = buf->capacity - buf->len;

    /* Return early if there's no work */
    if (remaining_capacity == 0) {
        return AWS_OP_SUCCESS;
    }

    DWORD bytes_to_read = remaining_capacity > MAXDWORD ? MAXDWORD : (DWORD)remaining_capacity;
    DWORD bytes_read;

    /* https://msdn.microsoft.com/en-us/library/aa365605(v=vs.85).aspx
     *     When the pipe is empty...
     *     using a nonblocking-wait handle, the function returns zero immediately,
     *     and the GetLastError function returns ERROR_NO_DATA.
     */
    bool success = ReadFile(handle->handle.dataptr, buf->buffer + buf->len, bytes_to_read, &bytes_read, NULL/*lpOverlapped*/);

    if (!success) {
        if (GetLastError() == ERROR_NO_DATA) {
            return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
        }

        return raise_last_windows_error();
    }

    buf->len += bytes_read;

    if (amount_read) {
        *amount_read = bytes_read;
    }

    return AWS_OP_SUCCESS;
}

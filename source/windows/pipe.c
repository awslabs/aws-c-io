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

#define PIPE_BUFFER_BYTES 4096

#define PIPE_PARTIAL_WRITE_RETRY_RSHIFT 2
#define PIPE_PARTIAL_WRITE_RETRY_MIN 128

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

#if 0 // named pipes
    /* Using named pipes, instead of anonymous pipes, because only named pipes support non-blocking IO.
     * Named pipes require that we specify a unique name. */
    char pipe_name[64];
    _snprintf_s(pipe_name, sizeof(pipe_name), _TRUNCATE, "\\\\.\\pipe\\%d", rand());// uuid_string); TODO: better random

    write_handle->handle.dataptr = CreateNamedPipe(
        pipe_name, /*lpName*/
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE, /*dwOpenMode*/
        PIPE_NOWAIT | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, /*dwPipeMode*/
        1, /*nMaxInstances*/
        PIPE_BUFFER_BYTES, /*nOutBufferSize*/
        PIPE_BUFFER_BYTES, /*nInBufferSize*/
        0, /*nDefaultTimeout: 0 means default*/
        NULL); /*lpSecurityAttributes: NULL results in default security and handle cannot be inerited*/

    if (write_handle->handle.dataptr == INVALID_HANDLE_VALUE) {
        goto clean_up;
    }

    read_handle->handle.dataptr = CreateFile(
        pipe_name, /*lpFileName*/
        GENERIC_READ, /*dwDesiredAccess*/
        0, /*dwShareMode*/
        NULL, /*lpSecurityAttributes: 0 means default*/
        OPEN_EXISTING, /*dwCreationDisposition*/
        0, /*dwFlagsAndAttributes: 0 means default*/
        NULL); /*hTemplateFile: ignored when opening existing file*/

    if (read_handle->handle.dataptr == INVALID_HANDLE_VALUE) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    if (write_handle->handle.dataptr != INVALID_HANDLE_VALUE) {
        CloseHandle(write_handle->handle.dataptr);
        write_handle->handle.dataptr = INVALID_HANDLE_VALUE;
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
#else // anonymous pipes
    bool success = CreatePipe(&read_handle->handle.dataptr, &write_handle->handle.dataptr, NULL, PIPE_BUFFER_BYTES);
    assert(success);

    DWORD read_mode = PIPE_NOWAIT | PIPE_READMODE_BYTE;
    success = SetNamedPipeHandleState(read_handle->handle.dataptr, &read_mode, NULL, NULL);
    assert(success);

    DWORD write_mode = PIPE_NOWAIT | PIPE_TYPE_BYTE;
    success = SetNamedPipeHandleState(write_handle->handle.dataptr, &write_mode, NULL, NULL);
    assert(success);

    return AWS_OP_SUCCESS;
#endif
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

#if 1 // partial write retry
    DWORD bytes_to_write = cursor->len > PIPE_BUFFER_BYTES ? PIPE_BUFFER_BYTES : (DWORD)cursor->len;
    DWORD bytes_written;

    /* https://msdn.microsoft.com/en-us/library/aa365605(v=vs.85).aspx
     * When there is insufficient space in the pipe's buffer...
     * with a nonblocking-wait handle, the write operation returns a nonzero value immediately
     * ... after writing as many bytes as the buffer holds. */
    while (true) {
        bool success = WriteFile(handle->handle.dataptr, cursor->ptr, bytes_to_write, &bytes_written, NULL/*lpOverlapped*/);
        if (!success) {
            return raise_last_windows_error();
        }

        if (bytes_written > 0) {
            break;
        }

        if (bytes_to_write < PIPE_PARTIAL_WRITE_RETRY_MIN) {
            return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
        }

        bytes_to_write = bytes_to_write >> PIPE_PARTIAL_WRITE_RETRY_RSHIFT;
    }
#else
    DWORD bytes_to_write = cursor->len > MAXDWORD ? MAXDWORD : (DWORD)cursor->len;
    DWORD bytes_written;

    bool success = WriteFile(handle->handle.dataptr, cursor->ptr, bytes_to_write, &bytes_written, NULL/*lpOverlapped*/);
    if (!success) {
        return raise_last_windows_error();
    }

    if (bytes_written == 0) {
        return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
    }
#endif

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
     * When the pipe is empty... using a nonblocking-wait handle,
     * the function returns zero immediately, and the GetLastError function returns ERROR_NO_DATA.
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

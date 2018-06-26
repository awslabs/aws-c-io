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
    read_handle->data.handle = INVALID_HANDLE_VALUE;
    write_handle->data.handle = INVALID_HANDLE_VALUE;
    read_handle->additional_data = NULL;
    write_handle->additional_data = NULL;

    bool success = CreatePipe(
            &read_handle->data.handle, /*read handle*/
            &write_handle->data.handle, /*write handle*/
            NULL, /*NULL means default security attributes*/
            SUGGESTED_BUFFER_SIZE); /*suggested size, in bytes, for the pipe's buffer*/
    if (!success) {
        return raise_last_windows_error();
    }

    /* We use anonymous pipes (rather than named pipes) because they "require less overhead".
     * It's possible to set non-blocking IO on an anonymous pipe via SetNamedPipeHandleState() */
    DWORD read_mode = PIPE_NOWAIT | PIPE_READMODE_BYTE;
    success = SetNamedPipeHandleState(
            read_handle->data.handle, /*pipe handle*/
            &read_mode, /*mode to set*/
            NULL, /*NULL if the collection count is not being set*/
            NULL); /*NULL if the collection count is not being set*/
    if (!success) {
        raise_last_windows_error();
        goto clean_up;
    }

    DWORD write_mode = PIPE_NOWAIT | PIPE_TYPE_BYTE;
    success = SetNamedPipeHandleState(
            write_handle->data.handle, /*pipe handle*/
            &write_mode, /*mode to set*/
            NULL, /*NULL if the collection count is not being set*/
            NULL); /*NULL if the collection count is not being set*/
    if (!success) {
        raise_last_windows_error();
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    CloseHandle(read_handle->data.handle);
    CloseHandle(write_handle->data.handle);
    return AWS_OP_ERR;
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

    HANDLE h = handle->data.handle;
    handle->data.handle = INVALID_HANDLE_VALUE;

    if (!CloseHandle(h)) {
        return raise_last_windows_error();
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_write(struct aws_io_handle *handle, const uint8_t *src, size_t src_size, size_t *written) {
    assert(handle);
    assert(src);

    if (written) {
        *written = 0;
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
    DWORD bytes_to_write = src_size > SUGGESTED_BUFFER_SIZE ? SUGGESTED_BUFFER_SIZE : (DWORD)src_size;
    DWORD bytes_written;
    while (true) {
        if (!WriteFile(handle->data.handle, src, bytes_to_write, &bytes_written, NULL/*lpOverlapped*/)) {
            return raise_last_windows_error();
        }

        if (bytes_written > 0 || bytes_to_write == 0) {
            break;
        }

        bytes_to_write = bytes_to_write >> PARTIAL_WRITE_RETRY_RSHIFT;
        if (bytes_to_write < PARTIAL_WRITE_RETRY_MIN) {
            return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
        }
    }

    if (written) {
        *written = bytes_written;
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_read(struct aws_io_handle *handle, uint8_t *dst, size_t dst_size, size_t *amount_read) {
    assert(handle);
    assert(dst);

    if (amount_read) {
        *amount_read = 0;
    }

    DWORD bytes_to_read = dst_size > MAXDWORD ? MAXDWORD : (DWORD)dst_size;
    DWORD bytes_read;

    /* https://msdn.microsoft.com/en-us/library/aa365605(v=vs.85).aspx
     *     When the pipe is empty...
     *     using a nonblocking-wait handle, the function returns zero immediately,
     *     and the GetLastError function returns ERROR_NO_DATA.
     */
    bool success = ReadFile(handle->data.handle, dst, bytes_to_read, &bytes_read, NULL/*lpOverlapped*/);

    if (!success) {
        if (GetLastError() == ERROR_NO_DATA) {
            return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
        }

        return raise_last_windows_error();
    }

    if (amount_read) {
        *amount_read = bytes_read;
    }

    return AWS_OP_SUCCESS;
}

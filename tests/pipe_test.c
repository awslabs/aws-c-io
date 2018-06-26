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
#include <aws/common/byte_buf.h>
#include <aws/io/io.h>
#include <aws/io/pipe.h>
#include <aws/testing/aws_test_harness.h>

static int test_pipe_open_close(struct aws_allocator *alloc, void *user_data) {
    struct aws_io_handle read, write;
    ASSERT_SUCCESS(aws_pipe_open(&read, &write));

    ASSERT_SUCCESS(aws_pipe_close(&read, &write));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_open_close, test_pipe_open_close);

/* Copy from buf_src to buf_dst using the pipe.
 * Assert that both buffers are identical when the work is done. */
static int copy_buffers_via_pipe(
        struct aws_io_handle *read_handle,
        struct aws_io_handle *write_handle,
        const uint8_t *buf_src,
        uint8_t *buf_dst,
        size_t buf_size) {

    size_t total_bytes_written = 0;
    size_t total_bytes_read = 0;

    struct aws_byte_cursor src_cursor = aws_byte_cursor_from_array(buf_src, buf_size);
    struct aws_byte_cursor dst_cursor = aws_byte_cursor_from_array(buf_dst, buf_size);

    /* In a loop, write as much as possible and read as much as possible.
     * AWS_IO_***_WOULD_BLOCK errors are expected when writing to a
     * full pipe or reading from an empty pipe */
    while (total_bytes_read < buf_size) {
        while (total_bytes_written < buf_size) {
            size_t bytes_written;
            int write_res = aws_pipe_write(write_handle, src_cursor.ptr, src_cursor.len, &bytes_written);
            if (write_res == AWS_OP_SUCCESS) {
                total_bytes_written += bytes_written;
                aws_byte_cursor_advance(&src_cursor, bytes_written);
            }
            else {
                ASSERT_INT_EQUALS(AWS_IO_WRITE_WOULD_BLOCK, aws_last_error());
                break;
            }
        }

        while (total_bytes_read < buf_size) {
            size_t bytes_read;
            int read_res = aws_pipe_read(read_handle, dst_cursor.ptr, dst_cursor.len, &bytes_read);
            if (read_res == AWS_OP_SUCCESS) {
                total_bytes_read += bytes_read;
                aws_byte_cursor_advance(&dst_cursor, bytes_read);
            }
            else {
                ASSERT_INT_EQUALS(AWS_IO_READ_WOULD_BLOCK, aws_last_error());
                break;
            }
        }
    }

    ASSERT_UINT_EQUALS(buf_size, total_bytes_read);
    ASSERT_UINT_EQUALS(buf_size, total_bytes_written);
    ASSERT_BIN_ARRAYS_EQUALS(buf_src, buf_size, buf_dst, buf_size);
    return AWS_OP_SUCCESS;
}

static int test_pipe_read_write(struct aws_allocator *alloc, void *user_data) {
    struct aws_io_handle read_handle, write_handle;
    ASSERT_SUCCESS(aws_pipe_open(&read_handle, &write_handle));

    uint8_t src_array[4] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t dst_array[4] = { 0 };

    ASSERT_SUCCESS(copy_buffers_via_pipe(&read_handle, &write_handle, src_array, dst_array, sizeof(src_array)));

    ASSERT_SUCCESS(aws_pipe_close(&read_handle, &write_handle));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_read_write, test_pipe_read_write);

static int test_pipe_read_write_large_buffer(struct aws_allocator *alloc, void *user_data) {
    struct aws_io_handle read_handle, write_handle;
    ASSERT_SUCCESS(aws_pipe_open(&read_handle, &write_handle));

    const size_t buffer_size = 1024 * 1024 * 5; /* 5MB */
    uint8_t *src_buf = aws_mem_acquire(alloc, buffer_size);
    ASSERT_NOT_NULL(src_buf);

    /* Fill buffer with random bytes */
    struct aws_byte_cursor src_cursor = aws_byte_cursor_from_array(src_buf, buffer_size);
    for (size_t i = 0; i < buffer_size; ++i) {
        aws_byte_cursor_write_u8(&src_cursor, (uint8_t)(rand() % 256));
    }

    uint8_t *dst_buf = aws_mem_acquire(alloc, buffer_size);
    ASSERT_NOT_NULL(dst_buf);

    ASSERT_SUCCESS(copy_buffers_via_pipe(&read_handle, &write_handle, src_buf, dst_buf, buffer_size));

    aws_mem_release(alloc, src_buf);
    aws_mem_release(alloc, dst_buf);
    ASSERT_SUCCESS(aws_pipe_close(&read_handle, &write_handle));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_read_write_large_buffer, test_pipe_read_write_large_buffer);

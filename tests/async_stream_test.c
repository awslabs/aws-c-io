/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/async_stream.h>

#include <aws/common/clock.h>
#include <aws/io/future.h>
#include <aws/testing/async_stream_tester.h>
#include <aws/testing/aws_test_harness.h>
#include <aws/testing/stream_tester.h>

#define ONE_SEC_IN_NS ((uint64_t)AWS_TIMESTAMP_NANOS)
#define MAX_TIMEOUT_NS (10 * ONE_SEC_IN_NS)

/* Common implementation for async_input_stream_fill_completes_on_XYZ() tests */
static int s_test_async_input_stream_read_to_fill(
    struct aws_allocator *alloc,
    struct aws_async_input_stream_tester_options *options) {

    aws_io_library_init(alloc);

    options->base.source_bytes = aws_byte_cursor_from_c_str("123456789");
    struct aws_async_input_stream *async_stream = aws_async_input_stream_new_tester(alloc, options);

    /* read into slightly short buffer */
    struct aws_byte_buf buf;
    aws_byte_buf_init(&buf, alloc, 5);

    struct aws_future_bool *read_future = aws_async_input_stream_read_to_fill(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    ASSERT_BIN_ARRAYS_EQUALS("12345", 5, buf.buffer, buf.len);
    bool eof = aws_future_bool_get_result(read_future);
    ASSERT_FALSE(eof);
    aws_future_bool_release(read_future);

    /* read the rest */
    buf.len = 0;
    read_future = aws_async_input_stream_read_to_fill(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    ASSERT_BIN_ARRAYS_EQUALS("6789", 4, buf.buffer, buf.len);
    eof = aws_future_bool_get_result(read_future);
    ASSERT_TRUE(eof);
    aws_future_bool_release(read_future);

    /* cleanup */
    aws_byte_buf_clean_up(&buf);
    aws_async_input_stream_release(async_stream);
    aws_io_library_clean_up();
    return 0;
}

/* Test aws_async_input_stream_read_to_fill()
 * Ensure it works when reads always complete on another thread. */
AWS_TEST_CASE(async_input_stream_fill_completes_on_thread, s_test_async_input_stream_fill_completes_on_thread)
static int s_test_async_input_stream_fill_completes_on_thread(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_async_input_stream_tester_options options = {
        .completion_strategy = AWS_ASYNC_READ_COMPLETES_ON_ANOTHER_THREAD,
        .base = {.max_bytes_per_read = 1},
    };
    return s_test_async_input_stream_read_to_fill(alloc, &options);
}

/* Test aws_async_input_stream_read_to_fill()
 * Ensure it works when reads always complete immediately */
AWS_TEST_CASE(async_input_stream_fill_completes_immediately, s_test_async_input_stream_fill_completes_immediately)
static int s_test_async_input_stream_fill_completes_immediately(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_async_input_stream_tester_options options = {
        .completion_strategy = AWS_ASYNC_READ_COMPLETES_IMMEDIATELY,
        .base = {.max_bytes_per_read = 1},
    };
    return s_test_async_input_stream_read_to_fill(alloc, &options);
}

/* Test aws_async_input_stream_read_to_fill()
 * Ensure it works when it's kinda random which thread completes the read */
AWS_TEST_CASE(async_input_stream_fill_completes_randomly, s_test_async_input_stream_fill_completes_randomly)
static int s_test_async_input_stream_fill_completes_randomly(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_async_input_stream_tester_options options = {
        .completion_strategy = AWS_ASYNC_READ_COMPLETES_ON_RANDOM_THREAD,
        .base = {.max_bytes_per_read = 1},
    };
    return s_test_async_input_stream_read_to_fill(alloc, &options);
}

/* Test aws_async_input_stream_read_to_fill()
 * Ensure that it works when it takes one more read to realize we're at EOF */
AWS_TEST_CASE(async_input_stream_fill_eof_requires_extra_read, s_test_async_input_stream_fill_eof_requires_extra_read)
static int s_test_async_input_stream_fill_eof_requires_extra_read(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_async_input_stream_tester_options options = {
        .base =
            {
                .source_bytes = aws_byte_cursor_from_c_str("123456789"),
                .eof_requires_extra_read = true,
            },
    };
    struct aws_async_input_stream *async_stream = aws_async_input_stream_new_tester(alloc, &options);

    /* read into buffer of the exact length. we shouldn't realize it's at EOF yet */
    struct aws_byte_buf buf;
    aws_byte_buf_init(&buf, alloc, 9);

    struct aws_future_bool *read_future = aws_async_input_stream_read_to_fill(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    ASSERT_BIN_ARRAYS_EQUALS("123456789", 9, buf.buffer, buf.len);
    bool eof = aws_future_bool_get_result(read_future);
    ASSERT_FALSE(eof);
    aws_future_bool_release(read_future);

    /* read again, get no data, but learn it's at EOF */
    buf.len = 0;
    read_future = aws_async_input_stream_read_to_fill(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    ASSERT_UINT_EQUALS(0, buf.len);
    eof = aws_future_bool_get_result(read_future);
    ASSERT_TRUE(eof);
    aws_future_bool_release(read_future);

    /* cleanup */
    aws_byte_buf_clean_up(&buf);
    aws_async_input_stream_release(async_stream);
    aws_io_library_clean_up();
    return 0;
}

/* Test aws_async_input_stream_read_to_fill()
 * Ensure that it reports errors from an underlying read() call */
AWS_TEST_CASE(async_input_stream_fill_reports_error, s_test_async_input_stream_fill_reports_error)
static int s_test_async_input_stream_fill_reports_error(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_async_input_stream_tester_options options = {
        .base =
            {
                .source_bytes = aws_byte_cursor_from_c_str("123456789"),
                .max_bytes_per_read = 1,
                .fail_on_nth_read = 2,
                .fail_with_error_code = 999,
            },
    };
    struct aws_async_input_stream *async_stream = aws_async_input_stream_new_tester(alloc, &options);

    /* read into buffer */
    struct aws_byte_buf buf;
    aws_byte_buf_init(&buf, alloc, 512);

    struct aws_future_bool *read_future = aws_async_input_stream_read_to_fill(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(999, aws_future_bool_get_error(read_future));
    aws_future_bool_release(read_future);

    /* cleanup */
    aws_byte_buf_clean_up(&buf);
    aws_async_input_stream_release(async_stream);
    aws_io_library_clean_up();
    return 0;
}

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

/* Helper function to create a new aws_async_input_stream that wraps a synchronous "tester" stream */
static struct aws_async_input_stream *s_new_async_stream_wrapping_synchronous_tester(
    struct aws_allocator *alloc,
    const struct aws_input_stream_tester_options *options) {

    struct aws_input_stream *sync_tester = aws_input_stream_new_tester(alloc, options);
    struct aws_async_input_stream *async_stream = aws_async_input_stream_new_from_synchronous(alloc, sync_tester);
    aws_input_stream_release(sync_tester);
    return async_stream;
}

/* Test aws_async_input_stream_new_from_synchronous()
 * Ensure it can do basic reads */
static int s_test_async_input_stream_wrapping_sync_simple(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    /* create an aws_async_input_stream wrapping an aws_input_stream_tester */
    struct aws_input_stream_tester_options options = {
        .source_bytes = aws_byte_cursor_from_c_str("1234"),
    };
    struct aws_async_input_stream *async_stream = s_new_async_stream_wrapping_synchronous_tester(alloc, &options);

    /* read first 2 bytes */
    struct aws_byte_buf buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&buf, alloc, 2));

    struct aws_future_bool *read_future = aws_async_input_stream_read(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    bool eof = aws_future_bool_get_result(read_future);
    ASSERT_FALSE(eof);
    ASSERT_BIN_ARRAYS_EQUALS("12", 2, buf.buffer, buf.len);
    read_future = aws_future_bool_release(read_future);

    /* read last 2 bytes */
    buf.len = 0; /* reset buf */
    read_future = aws_async_input_stream_read(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    eof = aws_future_bool_get_result(read_future);
    ASSERT_TRUE(eof);
    ASSERT_BIN_ARRAYS_EQUALS("34", 2, buf.buffer, buf.len);
    read_future = aws_future_bool_release(read_future);

    /* cleanup */
    aws_async_input_stream_release(async_stream);
    aws_byte_buf_clean_up(&buf);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(async_input_stream_wrapping_sync_simple, s_test_async_input_stream_wrapping_sync_simple)

/* Test aws_async_input_stream_new_from_synchronous()
 * Ensure it reports a read error */
static int s_test_async_input_stream_wrapping_sync_reports_error(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    /* create an aws_async_input_stream wrapping an aws_input_stream_tester */
    struct aws_input_stream_tester_options options = {
        .source_bytes = aws_byte_cursor_from_c_str("abcdefg"),
        .fail_on_nth_read = 1,
        .fail_with_error_code = 999,
    };
    struct aws_async_input_stream *async_stream = s_new_async_stream_wrapping_synchronous_tester(alloc, &options);

    /* read */
    struct aws_byte_buf buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&buf, alloc, 512));

    struct aws_future_bool *read_future = aws_async_input_stream_read(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));

    /* the async stream should report the error from the underlying synchronous stream */
    ASSERT_INT_EQUALS(999, aws_future_bool_get_error(read_future));
    read_future = aws_future_bool_release(read_future);

    /* cleanup */
    aws_async_input_stream_release(async_stream);
    aws_byte_buf_clean_up(&buf);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(async_input_stream_wrapping_sync_reports_error, s_test_async_input_stream_wrapping_sync_reports_error)

/* Test aws_async_input_stream_new_from_synchronous().
 * Ensure it retries after a zero-byte read until something is read */
static int s_test_async_input_stream_wrapping_sync_retries_zero_byte_reads(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    /* create an aws_async_input_stream wrapping an aws_input_stream_tester */
    struct aws_input_stream_tester_options options = {
        .source_bytes = aws_byte_cursor_from_c_str("abcdefg"),
        .read_zero_bytes_on_nth_read = 1,
    };
    struct aws_async_input_stream *async_stream = s_new_async_stream_wrapping_synchronous_tester(alloc, &options);

    /* read */
    struct aws_byte_buf buf;
    ASSERT_SUCCESS(aws_byte_buf_init(&buf, alloc, 512));

    struct aws_future_bool *read_future = aws_async_input_stream_read(async_stream, &buf);
    ASSERT_TRUE(aws_future_bool_wait(read_future, MAX_TIMEOUT_NS));

    /* even though the first read on the underlying stream gave 0 bytes,
     * the wrapping async stream should retry until it gets some data */
    ASSERT_INT_EQUALS(0, aws_future_bool_get_error(read_future));
    ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&options.source_bytes, &buf));
    bool eof = aws_future_bool_get_result(read_future);
    ASSERT_TRUE(eof);
    read_future = aws_future_bool_release(read_future);

    /* cleanup */
    aws_async_input_stream_release(async_stream);
    aws_byte_buf_clean_up(&buf);
    aws_io_library_clean_up();
    return 0;
}
AWS_TEST_CASE(
    async_input_stream_wrapping_sync_retries_zero_byte_reads,
    s_test_async_input_stream_wrapping_sync_retries_zero_byte_reads)

/* Common implementation for async_input_stream_read_to_fill_completes_on_XYZ() tests */
static int s_test_async_input_stream_read_to_fill(
    struct aws_allocator *alloc,
    struct aws_async_input_stream_tester_options *options) {

    aws_io_library_init(alloc);

    options->source_bytes = aws_byte_cursor_from_c_str("123456789");
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
static int s_test_async_input_stream_read_to_fill_completes_on_another_thread(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_async_input_stream_tester_options options = {
        .completion_strategy = AWS_AIST_READ_COMPLETES_ON_ANOTHER_THREAD,
        .max_bytes_per_read = 1,
    };
    return s_test_async_input_stream_read_to_fill(alloc, &options);
}
AWS_TEST_CASE(
    async_input_stream_read_to_fill_completes_on_another_thread,
    s_test_async_input_stream_read_to_fill_completes_on_another_thread)

/* Test aws_async_input_stream_read_to_fill()
 * Ensure it works when reads always complete immediately */
static int s_test_async_input_stream_read_to_fill_completes_immediately(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_async_input_stream_tester_options options = {
        .completion_strategy = AWS_AIST_READ_COMPLETES_IMMEDIATELY,
        .max_bytes_per_read = 1,
    };
    return s_test_async_input_stream_read_to_fill(alloc, &options);
}
AWS_TEST_CASE(
    async_input_stream_read_to_fill_completes_immediately,
    s_test_async_input_stream_read_to_fill_completes_immediately)

/* Test aws_async_input_stream_read_to_fill()
 * Ensure it works when it's kinda random which thread completes the read */
static int s_test_async_input_stream_read_to_fill_completes_on_random_thread(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    struct aws_async_input_stream_tester_options options = {
        .completion_strategy = AWS_AIST_READ_COMPLETES_ON_RANDOM_THREAD,
        .max_bytes_per_read = 1,
    };
    return s_test_async_input_stream_read_to_fill(alloc, &options);
}
AWS_TEST_CASE(
    async_input_stream_read_to_fill_completes_on_random_thread,
    s_test_async_input_stream_read_to_fill_completes_on_random_thread)

/* Test aws_async_input_stream_read_to_fill()
 * Ensure that it works when it takes one more read to realize we're at EOF */
static int s_test_async_input_stream_read_to_fill_when_eof_requires_extra_read(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_async_input_stream_tester_options options = {
        .source_bytes = aws_byte_cursor_from_c_str("123456789"),
        .eof_requires_extra_read = true,
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
AWS_TEST_CASE(
    async_input_stream_read_to_fill_when_eof_requires_extra_read,
    s_test_async_input_stream_read_to_fill_when_eof_requires_extra_read)

/* Test aws_async_input_stream_read_to_fill()
 * Ensure that it reports errors from an underlying read() call */
static int s_test_async_input_stream_read_to_fill_reports_error(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
    aws_io_library_init(alloc);

    struct aws_async_input_stream_tester_options options = {
        .source_bytes = aws_byte_cursor_from_c_str("123456789"),
        .max_bytes_per_read = 1,
        .fail_on_nth_read = 2,
        .fail_with_error_code = 999,
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
AWS_TEST_CASE(async_input_stream_read_to_fill_reports_error, s_test_async_input_stream_read_to_fill_reports_error)

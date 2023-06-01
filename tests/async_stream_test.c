/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/async_stream.h>

#include <aws/common/clock.h>
#include <aws/io/future.h>
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

/* Test aws_async_input_stream_new_from_synchronous() - that is can do basic reads */
static int s_test_async_input_stream_wrapping_sync_simple(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
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
    return 0;
}
AWS_TEST_CASE(async_input_stream_wrapping_sync_simple, s_test_async_input_stream_wrapping_sync_simple)

/* Test aws_async_input_stream_new_from_synchronous() - that it reports a read error */
static int s_test_async_input_stream_wrapping_sync_reports_error(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
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
    return 0;
}
AWS_TEST_CASE(async_input_stream_wrapping_sync_reports_error, s_test_async_input_stream_wrapping_sync_reports_error)

/* Test aws_async_input_stream_new_from_synchronous() - that it retries after a zero-byte read until something is read
 */
static int s_test_async_input_stream_wrapping_sync_retries_zero_byte_reads(struct aws_allocator *alloc, void *ctx) {
    (void)ctx;
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
    return 0;
}
AWS_TEST_CASE(
    async_input_stream_wrapping_sync_retries_zero_byte_reads,
    s_test_async_input_stream_wrapping_sync_retries_zero_byte_reads)

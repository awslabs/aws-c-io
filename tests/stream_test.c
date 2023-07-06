/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/common/file.h>
#include <aws/common/string.h>
#include <aws/io/stream.h>

#include <sys/stat.h>

#ifdef _WIN32
#    include <io.h>
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_simple_test, "SimpleTest");

/* 0x1A represents the Windows end-of-file character. Having this in the test data set allows us to verify that file
 * stream reads on binary files do not terminate early on Windows.*/
const uint8_t s_simple_binary_test[] = {'a', 'b', 'c', 'd', 'e', 'f', 0x1A, 'g', 'h', 'i', 'j', 'k'};

static struct aws_input_stream *s_create_memory_stream(struct aws_allocator *allocator) {
    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    return aws_input_stream_new_from_cursor(allocator, &test_cursor);
}

static void s_destroy_memory_stream(struct aws_input_stream *stream) {
    aws_input_stream_destroy(stream);
}

static struct aws_input_stream *s_create_file_stream(struct aws_allocator *allocator, const char *file_path) {
    remove(file_path);

    FILE *file = aws_fopen(file_path, "w");
    fprintf(file, "%s", (char *)s_simple_test->bytes);
    fclose(file);

    return aws_input_stream_new_from_file(allocator, file_path);
}

static struct aws_input_stream *s_create_binary_file_stream(struct aws_allocator *allocator, const char *file_path) {
    remove(file_path);

    FILE *file = aws_fopen(file_path, "wb");
    fwrite(s_simple_binary_test, sizeof(uint8_t), sizeof(s_simple_binary_test), file);
    fclose(file);

    return aws_input_stream_new_from_file(allocator, file_path);
}

static struct aws_input_stream *s_create_read_only_file_stream(struct aws_allocator *allocator, const char *file_path) {
    remove(file_path);

    FILE *file = aws_fopen(file_path, "w");
    fprintf(file, "%s", (char *)s_simple_test->bytes);
    fclose(file);
#ifdef _WIN32
    if (_chmod(file_path, _S_IREAD)) {
        return NULL;
    }
#else
    if (chmod(file_path, S_IRUSR | S_IRGRP | S_IROTH)) {
        return NULL;
    }
#endif
    return aws_input_stream_new_from_file(allocator, file_path);
}

static void s_destroy_file_stream(struct aws_input_stream *stream, const char *file_path) {
    aws_input_stream_destroy(stream);

    remove(file_path);
}

static int s_do_simple_input_stream_test(
    struct aws_input_stream *stream,
    struct aws_allocator *allocator,
    size_t read_buf_size,
    struct aws_byte_cursor *expected_contents) {
    struct aws_byte_buf read_buf;
    aws_byte_buf_init(&read_buf, allocator, read_buf_size);

    struct aws_byte_buf result_buf;
    aws_byte_buf_init(&result_buf, allocator, 1024);

    struct aws_stream_status status;
    AWS_ZERO_STRUCT(status);

    ASSERT_TRUE(aws_input_stream_get_status(stream, &status) == 0);
    ASSERT_TRUE(status.is_end_of_stream == false);

    while (!status.is_end_of_stream) {
        const size_t starting_len = read_buf.len;
        ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));

        if (starting_len - read_buf.len > 0) {
            struct aws_byte_cursor dest_cursor = aws_byte_cursor_from_buf(&read_buf);
            aws_byte_buf_append_dynamic(&result_buf, &dest_cursor);
        }

        read_buf.len = 0;

        ASSERT_TRUE(aws_input_stream_get_status(stream, &status) == 0);
    }

    struct aws_byte_cursor result_cursor = aws_byte_cursor_from_buf(&result_buf);
    ASSERT_TRUE(aws_byte_cursor_eq(expected_contents, &result_cursor));

    aws_byte_buf_clean_up(&read_buf);
    aws_byte_buf_clean_up(&result_buf);

    return AWS_OP_SUCCESS;
}

static int s_test_input_stream_memory_simple(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 100, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_simple, s_test_input_stream_memory_simple);

static int s_test_input_stream_memory_iterate(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 2, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_iterate, s_test_input_stream_memory_iterate);

static int s_test_input_stream_file_simple(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_file_simple.txt"; /* unique name */
    struct aws_input_stream *stream = s_create_file_stream(allocator, file_path);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 100, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_simple, s_test_input_stream_file_simple);

static int s_test_input_stream_file_iterate(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_file_iterate.txt"; /* unique name */
    struct aws_input_stream *stream = s_create_file_stream(allocator, file_path);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 2, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_iterate, s_test_input_stream_file_iterate);

static int s_do_input_stream_seek_test(
    struct aws_input_stream *stream,
    struct aws_allocator *allocator,
    int64_t offset,
    enum aws_stream_seek_basis basis,
    struct aws_byte_cursor *expected_contents) {
    struct aws_byte_buf read_buf;
    aws_byte_buf_init(&read_buf, allocator, 1024);

    ASSERT_SUCCESS(aws_input_stream_seek(stream, offset, basis));

    ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));

    struct aws_byte_cursor read_buf_cursor = aws_byte_cursor_from_buf(&read_buf);
    ASSERT_TRUE(aws_byte_cursor_eq(expected_contents, &read_buf_cursor));

    aws_byte_buf_clean_up(&read_buf);

    return AWS_OP_SUCCESS;
}

#define SEEK_BEGINNING_OFFSET 5

static int s_test_input_stream_memory_seek_beginning(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    aws_byte_cursor_advance(&test_cursor, SEEK_BEGINNING_OFFSET);
    ASSERT_TRUE(
        s_do_input_stream_seek_test(stream, allocator, SEEK_BEGINNING_OFFSET, AWS_SSB_BEGIN, &test_cursor) ==
        AWS_OP_SUCCESS);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_beginning, s_test_input_stream_memory_seek_beginning);

static int s_test_input_stream_file_seek_beginning(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_file_seek_beginning.txt"; /* unique name */
    struct aws_input_stream *stream = s_create_file_stream(allocator, file_path);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    aws_byte_cursor_advance(&test_cursor, SEEK_BEGINNING_OFFSET);
    ASSERT_TRUE(
        s_do_input_stream_seek_test(stream, allocator, SEEK_BEGINNING_OFFSET, AWS_SSB_BEGIN, &test_cursor) ==
        AWS_OP_SUCCESS);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_seek_beginning, s_test_input_stream_file_seek_beginning);

#define SEEK_END_OFFSET (-3)

static int s_test_input_stream_memory_seek_end(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    aws_byte_cursor_advance(&test_cursor, (size_t)((int64_t)s_simple_test->len + SEEK_END_OFFSET));
    ASSERT_TRUE(
        s_do_input_stream_seek_test(stream, allocator, SEEK_END_OFFSET, AWS_SSB_END, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_end, s_test_input_stream_memory_seek_end);

static int s_test_input_stream_memory_seek_multiple_times(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *src_cstr = "0123456789";
    const struct aws_byte_cursor src_cursor = aws_byte_cursor_from_c_str(src_cstr);
    struct aws_input_stream *stream = aws_input_stream_new_from_cursor(allocator, &src_cursor);

    char read_byte = 0;
    struct aws_byte_buf read_buf = aws_byte_buf_from_empty_array(&read_byte, 1);

    /* Seek to BEGIN + 2. Read "2" */
    ASSERT_SUCCESS(aws_input_stream_seek(stream, 2, AWS_SSB_BEGIN));
    read_buf.len = 0;
    ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));
    ASSERT_INT_EQUALS('2', read_byte);

    /* Seek to BEGIN + 4. Read "4" */
    ASSERT_SUCCESS(aws_input_stream_seek(stream, 4, AWS_SSB_BEGIN));
    read_buf.len = 0;
    ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));
    ASSERT_INT_EQUALS('4', read_byte);

    /* Seek to END - 1. Read "9" */
    ASSERT_SUCCESS(aws_input_stream_seek(stream, -1, AWS_SSB_END));
    read_buf.len = 0;
    ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));
    ASSERT_INT_EQUALS('9', read_byte);

    /* Seek to END - 5. Read "5" */
    ASSERT_SUCCESS(aws_input_stream_seek(stream, -1, AWS_SSB_END));
    read_buf.len = 0;
    ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));
    ASSERT_INT_EQUALS('9', read_byte);

    /* Seek to BEGIN + 0. Read "0" */
    ASSERT_SUCCESS(aws_input_stream_seek(stream, 4, AWS_SSB_BEGIN));
    read_buf.len = 0;
    ASSERT_SUCCESS(aws_input_stream_read(stream, &read_buf));
    ASSERT_INT_EQUALS('4', read_byte);

    aws_input_stream_destroy(stream);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_multiple_times, s_test_input_stream_memory_seek_multiple_times);

static int s_test_input_stream_file_seek_end(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_file_seek_end.txt"; /* unique name */
    struct aws_input_stream *stream = s_create_file_stream(allocator, file_path);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    aws_byte_cursor_advance(&test_cursor, (size_t)((int64_t)s_simple_test->len + SEEK_END_OFFSET));
    ASSERT_TRUE(
        s_do_input_stream_seek_test(stream, allocator, SEEK_END_OFFSET, AWS_SSB_END, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_seek_end, s_test_input_stream_file_seek_end);

static int s_test_input_stream_memory_seek_past_end(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    ASSERT_TRUE(aws_input_stream_seek(stream, 13, AWS_SSB_BEGIN) == AWS_OP_ERR);
    ASSERT_TRUE(aws_last_error() == AWS_IO_STREAM_INVALID_SEEK_POSITION);

    aws_reset_error();

    ASSERT_TRUE(aws_input_stream_seek(stream, 1, AWS_SSB_END) == AWS_OP_ERR);
    ASSERT_TRUE(aws_last_error() == AWS_IO_STREAM_INVALID_SEEK_POSITION);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_past_end, s_test_input_stream_memory_seek_past_end);

static int s_test_input_stream_memory_seek_before_start(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    ASSERT_TRUE(aws_input_stream_seek(stream, -13, AWS_SSB_END) == AWS_OP_ERR);
    ASSERT_TRUE(aws_last_error() == AWS_IO_STREAM_INVALID_SEEK_POSITION);

    aws_reset_error();

    ASSERT_TRUE(aws_input_stream_seek(stream, -1, AWS_SSB_BEGIN) == AWS_OP_ERR);
    ASSERT_TRUE(aws_last_error() == AWS_IO_STREAM_INVALID_SEEK_POSITION);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_before_start, s_test_input_stream_memory_seek_before_start);

#define LENGTH_SEEK_OFFSET 3

static int s_test_input_stream_memory_length(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_memory_stream(allocator);

    int64_t length = 0;
    ASSERT_TRUE(aws_input_stream_get_length(stream, &length) == AWS_OP_SUCCESS);
    ASSERT_TRUE(length == (int64_t)s_simple_test->len);

    /* invariant under seeking */
    aws_input_stream_seek(stream, LENGTH_SEEK_OFFSET, AWS_SSB_BEGIN);

    ASSERT_TRUE(aws_input_stream_get_length(stream, &length) == AWS_OP_SUCCESS);
    ASSERT_TRUE(length == (int64_t)s_simple_test->len);

    s_destroy_memory_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_length, s_test_input_stream_memory_length);

static int s_test_input_stream_file_length(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_file_length.txt"; /* unique name */
    struct aws_input_stream *stream = s_create_file_stream(allocator, file_path);
    int64_t length = 0;
    ASSERT_TRUE(aws_input_stream_get_length(stream, &length) == AWS_OP_SUCCESS);
    ASSERT_TRUE(length == (int64_t)s_simple_test->len);

    /* invariant under seeking */
    aws_input_stream_seek(stream, LENGTH_SEEK_OFFSET, AWS_SSB_BEGIN);

    ASSERT_TRUE(aws_input_stream_get_length(stream, &length) == AWS_OP_SUCCESS);
    ASSERT_TRUE(length == (int64_t)s_simple_test->len);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_length, s_test_input_stream_file_length);

static int s_test_input_stream_binary(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_binary.dat"; /* unique name */
    struct aws_input_stream *stream = s_create_binary_file_stream(allocator, file_path);

    struct aws_byte_cursor test_cursor = {
        .ptr = (uint8_t *)s_simple_binary_test,
        .len = sizeof(s_simple_binary_test),
    };

    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 100, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_binary, s_test_input_stream_binary);

static int s_test_input_stream_read_only(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *file_path = "test_input_stream_read_only.txt"; /* unique name */
    struct aws_input_stream *stream = s_create_read_only_file_stream(allocator, file_path);
    ASSERT_NOT_NULL(stream);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 100, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream, file_path);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_read_only, s_test_input_stream_read_only);

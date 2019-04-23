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

#include <aws/testing/aws_test_harness.h>

#include <aws/common/string.h>
#include <aws/io/stream.h>

AWS_STATIC_STRING_FROM_LITERAL(s_simple_test, "SimpleTest");

const char *s_test_file_name = "stream.txt";

static struct aws_input_stream *s_create_memory_stream(struct aws_allocator *allocator) {
    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    return aws_input_stream_new_from_cursor(allocator, &test_cursor);
}

static void s_destroy_memory_stream(struct aws_input_stream *stream) {
    aws_input_stream_destroy(stream);
}

static struct aws_input_stream *s_create_file_stream(struct aws_allocator *allocator) {
    FILE *file = fopen(s_test_file_name, "w+");
    fprintf(file, "%s", (char *)s_simple_test->bytes);
    fclose(file);

    return aws_input_stream_new_from_file(allocator, s_test_file_name);
}

static void s_destroy_file_stream(struct aws_input_stream *stream) {
    aws_input_stream_destroy(stream);

    remove(s_test_file_name);
}

static int s_do_simple_input_stream_test(struct aws_input_stream *stream, struct aws_allocator *allocator, size_t read_buf_size, struct aws_byte_cursor *expected_contents) {
    struct aws_byte_buf read_buf;
    aws_byte_buf_init(&read_buf, allocator, read_buf_size);

    struct aws_byte_buf result_buf;
    aws_byte_buf_init(&result_buf, allocator, 1024);

    bool eof = false;
    ASSERT_TRUE(aws_input_stream_eof(stream, &eof) == 0);
    ASSERT_TRUE(eof == false);

    while (!eof) {
        size_t amount_read = 0;
        ASSERT_TRUE(aws_input_stream_read(stream, &read_buf, &amount_read) == 0);

        struct aws_byte_cursor dest_cursor = aws_byte_cursor_from_buf(&read_buf);
        aws_byte_buf_append_dynamic(&result_buf, &dest_cursor);

        read_buf.len = 0;

        ASSERT_TRUE(aws_input_stream_eof(stream, &eof) == 0);
    }

    struct aws_byte_cursor result_cursor = aws_byte_cursor_from_buf(&result_buf);
    ASSERT_TRUE(aws_byte_cursor_eq(expected_contents, &result_cursor));

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

    struct aws_input_stream *stream = s_create_file_stream(allocator);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 100, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_simple, s_test_input_stream_file_simple);

static int s_test_input_stream_file_iterate(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_input_stream *stream = s_create_file_stream(allocator);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    ASSERT_TRUE(s_do_simple_input_stream_test(stream, allocator, 2, &test_cursor) == AWS_OP_SUCCESS);

    s_destroy_file_stream(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_file_iterate, s_test_input_stream_file_iterate);


static int s_do_input_stream_seek_test(struct aws_input_stream *stream, struct aws_allocator *allocator, size_t offset, enum aws_stream_seek_basis basis, struct aws_byte_cursor *expected_contents) {
    struct aws_byte_buf read_buf;
    aws_byte_buf_init(&read_buf, allocator, 1024);

    ASSERT_TRUE(aws_input_stream_seek(stream, ))
        size_t amount_read = 0;
        ASSERT_TRUE(aws_input_stream_read(stream, &read_buf, &amount_read) == 0);

        struct aws_byte_cursor dest_cursor = aws_byte_cursor_from_buf(&read_buf);
        aws_byte_buf_append_dynamic(&result_buf, &dest_cursor);


    struct aws_byte_cursor result_cursor = aws_byte_cursor_from_buf(&result_buf);
    ASSERT_TRUE(aws_byte_cursor_eq(expected_contents, &result_cursor));

    return AWS_OP_SUCCESS;
}

#define SEEK_BEGINNING_OFFSET 5

static int s_test_input_stream_memory_seek_beginning(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_buf dest;
    aws_byte_buf_init(&dest, allocator, 100);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    struct aws_input_stream *stream = aws_input_stream_new_from_cursor(allocator, &test_cursor);
    ASSERT_TRUE(stream != NULL);

    ASSERT_TRUE(aws_input_stream_seek(stream, SEEK_BEGINNING_OFFSET, AWS_SSB_BEGIN) == AWS_OP_SUCCESS);

    bool eof = false;
    ASSERT_TRUE(aws_input_stream_eof(stream, &eof) == 0);
    ASSERT_TRUE(eof == false);

    size_t amount_read = 0;
    ASSERT_TRUE(aws_input_stream_read(stream, &dest, &amount_read) == AWS_OP_SUCCESS);
    ASSERT_TRUE(amount_read == s_simple_test->len - SEEK_BEGINNING_OFFSET);

    ASSERT_TRUE(aws_input_stream_eof(stream, &eof) == AWS_OP_SUCCESS);
    ASSERT_TRUE(eof == true);

    struct aws_byte_cursor dest_cursor = aws_byte_cursor_from_buf(&dest);
    ASSERT_TRUE(aws_byte_cursor_eq(&test_cursor, &dest_cursor));
    ASSERT_TRUE(strncmp((char *)s_simple_test->bytes + SEEK_BEGINNING_OFFSET, (char *)dest_cursor.ptr, amount_read) == AWS_OP_SUCCESS);

    aws_input_stream_destroy(stream);
    aws_byte_buf_clean_up(&dest);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_beginning, s_test_input_stream_memory_seek_beginning);

#define SEEK_END_OFFSET 3

static int s_test_input_stream_memory_seek_end(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_buf dest;
    aws_byte_buf_init(&dest, allocator, 100);

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    struct aws_input_stream *stream = aws_input_stream_new_from_cursor(allocator, &test_cursor);
    ASSERT_TRUE(stream != NULL);

    ASSERT_TRUE(aws_input_stream_seek(stream, SEEK_END_OFFSET, AWS_SSB_END) == AWS_OP_SUCCESS);

    bool eof = false;
    ASSERT_TRUE(aws_input_stream_eof(stream, &eof) == 0);
    ASSERT_TRUE(eof == false);

    size_t amount_read = 0;
    ASSERT_TRUE(aws_input_stream_read(stream, &dest, &amount_read) == AWS_OP_SUCCESS);
    ASSERT_TRUE(amount_read == SEEK_END_OFFSET);

    ASSERT_TRUE(aws_input_stream_eof(stream, &eof) == AWS_OP_SUCCESS);
    ASSERT_TRUE(eof == true);

    struct aws_byte_cursor dest_cursor = aws_byte_cursor_from_buf(&dest);
    ASSERT_TRUE(aws_byte_cursor_eq(&test_cursor, &dest_cursor));
    ASSERT_TRUE(strncmp((char *)s_simple_test->bytes + s_simple_test->len - SEEK_END_OFFSET, (char *)dest_cursor.ptr, amount_read) == AWS_OP_SUCCESS);

    aws_input_stream_destroy(stream);
    aws_byte_buf_clean_up(&dest);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_end, s_test_input_stream_memory_seek_end);

static int s_test_input_stream_memory_seek_invalid(struct aws_allocator *allocator, void *ctx) {
    (void) ctx;

    struct aws_byte_cursor test_cursor = aws_byte_cursor_from_string(s_simple_test);
    struct aws_input_stream *stream = aws_input_stream_new_from_cursor(allocator, &test_cursor);
    ASSERT_TRUE(stream != NULL);

    ASSERT_TRUE(aws_input_stream_seek(stream, s_simple_test->len + 3, AWS_SSB_BEGIN) == AWS_OP_ERR);
    ASSERT_TRUE(aws_last_error() == AWS_IO_STREAM_INVALID_SEEK_POSITION);

    aws_input_stream_destroy(stream);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_input_stream_memory_seek_invalid, s_test_input_stream_memory_seek_invalid);

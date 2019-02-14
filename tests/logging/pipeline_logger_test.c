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

#include <aws/io/pipeline_logger.h>

#include <aws/testing/aws_test_harness.h>

#include <errno.h>
#include <stdio.h>

#define TEST_PIPELINE_MAX_BUFFER_SIZE 4096

static const char *s_test_file_name =
#ifdef WIN32
        "C:\\temp\\aws_log_writer_test.log";
#else
        "/tmp/aws_log_writer_test.log";
#endif

typedef void(*log_test_fn)(void);

int do_pipeline_logger_test(log_test_fn log_fn, const char **expected_user_content, size_t user_content_count) {

    remove(s_test_file_name);

    struct aws_logger logger;
    if (aws_pipeline_logger_file_writer_init(&logger, aws_default_allocator(), AWS_LL_TRACE, s_test_file_name)) {
        return AWS_OP_ERR;
    }

    aws_logging_set(&logger);

    (*log_fn)();

    aws_logging_set(NULL);

    aws_logger_cleanup(&logger);

    char buffer[TEST_PIPELINE_MAX_BUFFER_SIZE];
    FILE *file = fopen(s_test_file_name, "r");
    int open_error = errno;
    size_t bytes_read = 0;

    if (file != NULL) {
        bytes_read = fread(buffer, 1, TEST_PIPELINE_MAX_BUFFER_SIZE - 1, file);
        fclose(file);
    }

    remove(s_test_file_name);

    /*
     * Check the file was read successfully
     */
    ASSERT_TRUE(file != NULL, "Unable to open log file \"%s\" to verify contents. Error: %d", s_test_file_name, open_error);
    ASSERT_TRUE(bytes_read >= 0, "Failed to read log file \"%s\"", s_test_file_name);

    /*
     * add end of string marker
     */
    buffer[bytes_read] = 0;

    /*
     * Timestamps prevent us from doing simple string comparisons to check the log file and writing a parser to pull out
     * log lines in the face of multi-line arbitrary content seems overkill.  Since we've already validated
     * the formatter via the formatter tests, the main thing to do here is just verify that the user part of the log
     * lines is making it to the log file.
     */
    const char *buffer_ptr = buffer;
    for (size_t i = 0; i < user_content_count; ++i) {
        buffer_ptr = strstr(buffer_ptr, expected_user_content[i]);
        ASSERT_TRUE(buffer_ptr != NULL, "Expected to find \"%s\" in log file but could not.  Content is either missing or out-of-order.", expected_user_content[i]);
    }

    return AWS_OP_SUCCESS;
}

static void s_unformatted_pipeline_logger_test_callback(void) {
    AWS_LOGF_TRACE("trace log call");
    AWS_LOGF_DEBUG("debug log call");
    AWS_LOGF_INFO("info log call");
    AWS_LOGF_WARN("warn log call");
    AWS_LOGF_ERROR("error log call");
    AWS_LOGF_FATAL("fatal log call");
}

static void s_formatted_pipeline_logger_test_callback(void) {
    AWS_LOGF_TRACE("%s log call", "trace");
    AWS_LOGF_DEBUG("%s log call", "debug");
    AWS_LOGF_INFO("%s log call", "info");
    AWS_LOGF_WARN("%s log call", "warn");
    AWS_LOGF_ERROR("%s log call", "error");
    AWS_LOGF_FATAL("%s log call", "fatal");
}

static const char *expected_test_user_content[] = {
    "trace log call",
    "debug log call",
    "info log call",
    "warn log call",
    "error log call",
    "fatal log call"
};

#define DEFINE_PIPELINE_LOGGER_TEST(test_name, callback_function)                                                                                               \
static int s_pipeline_logger_##test_name##_fn(struct aws_allocator *allocator, void *ctx) {                                                                     \
    (void) ctx;                                                                                                                                                 \
    return do_pipeline_logger_test(callback_function, expected_test_user_content, sizeof(expected_test_user_content) / sizeof(expected_test_user_content[0]));  \
}                                                                                                                                                               \
AWS_TEST_CASE(test_pipeline_logger_##test_name, s_pipeline_logger_##test_name##_fn);

DEFINE_PIPELINE_LOGGER_TEST(unformatted_test, s_unformatted_pipeline_logger_test_callback)
DEFINE_PIPELINE_LOGGER_TEST(formatted_test, s_formatted_pipeline_logger_test_callback)
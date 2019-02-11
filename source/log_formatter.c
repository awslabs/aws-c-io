/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/io/log_formatter.h>

#include <aws/common/date_time.h>
#include <aws/common/string.h>

#include <stdio.h>

/*
 * Default formatter implementation
 */
#define MAX_LOG_LINE_PREFIX_SIZE (20 + AWS_DATE_TIME_STR_MAX_LEN)

struct aws_default_log_formatter_impl {
    enum aws_date_format date_format;
};

static int s_default_aws_log_formatter_format_fn(
    struct aws_log_formatter *formatter,
    struct aws_string** formatted_output,
    enum aws_log_level level,
    aws_log_subject_t subject,
    const char *format,
    ...) {

    (void)subject;

    struct aws_default_log_formatter_impl *impl = (struct aws_default_log_formatter_impl *) formatter->impl;

    if (formatted_output == NULL) {
        return AWS_OP_ERR;
    }

    int result = AWS_OP_ERR;

    va_list args;
    va_start(args, format);

    /*
     * Calculate how much room we'll need to build the full log line.
     * You cannot consume a va_list twice, so we have to copy it.
     */
    va_list tmp_args;
    va_copy(tmp_args, args);
#ifdef WIN32
    int required_length = _vscprintf(format, tmp_args) + 1;
#else
    int required_length = vsnprintf(NULL, 0, format, tmp_args) + 1;
#endif
    va_end(tmp_args);

    int total_length = required_length + MAX_LOG_LINE_PREFIX_SIZE;

    /*
     * Allocate enough room to hold the line.  Then we'll (unsafely) do formatted IO directly into the memory.
     */
    struct aws_string *raw_string = (struct aws_string *)aws_mem_acquire(formatter->allocator, sizeof(struct aws_string) + total_length);
    if (raw_string == NULL) {
        goto cleanup;
    }

    char *log_line_buffer = (char *)raw_string->bytes;
    int current_index = 0;

    const char *level_string = NULL;
    if (aws_logging_log_level_to_string(level, &level_string)) {
        goto cleanup;
    }

    /*
     * Begin the log line with "[<Log Level>] "
     */
    int log_level_length = snprintf(log_line_buffer, total_length, "[%s] ", level_string);
    if (log_level_length < 0) {
        goto cleanup;
    }

    current_index += log_level_length;

    /*
     * Add the timestamp.  To avoid copies and allocations, do some byte buffer tomfoolery.
     *
     * First, make a byte_buf that points to the current position in the output string
     */
    struct aws_byte_buf timestamp_buffer;
    timestamp_buffer.allocator = formatter->allocator;
    timestamp_buffer.buffer = (uint8_t *)log_line_buffer + current_index;
    timestamp_buffer.capacity = total_length - current_index;
    timestamp_buffer.len = 0;

    /*
     * Output the current time to the byte_buf
     */
    struct aws_date_time current_time;
    aws_date_time_init_now(&current_time);

    result = aws_date_time_to_utc_time_str(&current_time, impl->date_format, &timestamp_buffer);
    if (result != AWS_OP_SUCCESS) {
        goto cleanup;
    }

    /*
     * Fixup the indexing
     */
    current_index += timestamp_buffer.len;

    /*
     * Add a separator (" - ") between the timestamp and the user content
     */
    int separator_length = snprintf(log_line_buffer + current_index, total_length - current_index, " - ");
    if (separator_length < 0) {
        goto cleanup;
    }

    current_index += separator_length;

    /*
     * Now write the actual data requested by the user
     */
#ifdef WIN32
    int written_count = vsnprintf_s(log_line_buffer + current_index, total_length - current_index, _TRUNCATE, format, args);
#else
    int written_count = vsnprintf(log_line_buffer + current_index, total_length - current_index, format, args);
#endif // WIN32
    if (written_count < 0) {
        goto cleanup;
    }

    /*
     * End with a newline.
     */
    current_index += written_count;
    written_count = snprintf(log_line_buffer + current_index, total_length - current_index, "\n");
    if (written_count < 0) {
        goto cleanup;
    }

    result = AWS_OP_SUCCESS;

    *(struct aws_allocator **) (&raw_string->allocator) = formatter->allocator;
    *(size_t *) (&raw_string->len) = current_index + written_count;

    *formatted_output = raw_string;

cleanup:

    va_end(args);

    if (result == AWS_OP_ERR && raw_string != NULL) {
        aws_mem_release(formatter->allocator, raw_string);
    }

    return result;
}

static int s_default_aws_log_formatter_cleanup_fn(struct aws_log_formatter *formatter) {
    aws_mem_release(formatter->allocator, formatter->impl);

    return AWS_OP_SUCCESS;
}

static struct aws_log_formatter_vtable s_default_log_formatter_vtable = {
    .format_fn = s_default_aws_log_formatter_format_fn,
    .cleanup_fn = s_default_aws_log_formatter_cleanup_fn
};


int aws_default_log_formatter_init(struct aws_log_formatter *formatter, struct aws_allocator *allocator, enum aws_date_format date_format) {
    struct aws_default_log_formatter_impl *impl = (struct aws_default_log_formatter_impl *)aws_mem_acquire(allocator, sizeof(struct aws_default_log_formatter_impl));
    impl->date_format = date_format;

    formatter->vtable = &s_default_log_formatter_vtable;
    formatter->allocator = allocator;
    formatter->impl = impl;

    return AWS_OP_SUCCESS;
}

int aws_log_formatter_cleanup(struct aws_log_formatter *formatter) {
    return (*formatter->vtable->cleanup_fn)(formatter);
}

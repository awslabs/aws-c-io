
#ifndef AWS_IO_LOG_FORMATTER_H
#define AWS_IO_LOG_FORMATTER_H

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


#include <aws/io/io.h>

#include <aws/common/date_time.h>
#include <aws/common/logging.h>

struct aws_allocator;
struct aws_string;

/*
 * Log formatter interface and default implementation
 *
 * Log formatters are invoked by the LOGF_* macros to transform a set of arguments into
 * one or more lines of text to be output to a logging sink.
 */
struct aws_log_formatter;

typedef int (*aws_log_formatter_format_fn)(
    struct aws_log_formatter *formatter,
    struct aws_string** formatted_output,
    enum aws_log_level level,
    aws_log_subject_t subject,
    const char *format,
    ...);

typedef int (*aws_log_formatter_cleanup_fn)(struct aws_log_formatter *logger);

struct aws_log_formatter_vtable {
    aws_log_formatter_format_fn format_fn;
    aws_log_formatter_cleanup_fn cleanup_fn;
};

struct aws_log_formatter {
    struct aws_log_formatter_vtable *vtable;
    struct aws_allocator *allocator;
    void *impl;
};

/*
 * Initializes the default log formatter which outputs lines in the format:
 *
 *   [<LogLevel>] <Timestamp> - <User content>\n
 */
AWS_IO_API
int aws_default_log_formatter_init(struct aws_log_formatter *formatter, struct aws_allocator *allocator, enum aws_date_format date_format);

/*
 * Cleans up a log formatter (minus the base structure memory) by calling the formatter's cleanup function
 * via the vtable.
 */
AWS_IO_API
int aws_log_formatter_cleanup(struct aws_log_formatter *formatter);

#endif /* AWS_IO_LOG_FORMATTER_H */

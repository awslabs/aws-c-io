
#ifndef AWS_IO_LOG_WRITER_H
#define AWS_IO_LOG_WRITER_H

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

struct aws_allocator;
struct aws_string;

/*
 * Log writer interface and default implementation(s)
 *
 * A log writer functions as a sink for formatted log lines.  We provide
 * default implementations that go to stdout, stderr, and a specified file.
 */
struct aws_log_writer;

typedef int (*aws_log_writer_write_fn)(struct aws_log_writer *writer, const struct aws_string *output);
typedef int (*aws_log_writer_cleanup_fn)(struct aws_log_writer *writer);

struct aws_log_writer_vtable {
    aws_log_writer_write_fn write_fn;
    aws_log_writer_cleanup_fn cleanup_fn;
};

struct aws_log_writer {
    struct aws_log_writer_vtable *vtable;
    struct aws_allocator *allocator;
    void *impl;
};

/*
 * Initialize a log writer that sends log lines to stdout.  Uses C library IO.
 */
AWS_IO_API
int aws_stdout_log_writer_init(struct aws_log_writer *writer, struct aws_allocator *allocator);

/*
 * Initialize a log writer that sends log lines to stderr.  Uses C library IO.
 */
AWS_IO_API
int aws_stderr_log_writer_init(struct aws_log_writer *writer, struct aws_allocator *allocator);

/*
 * Initialize a log writer that sends log lines to a file.  Uses C library IO.
 */
AWS_IO_API
int aws_file_log_writer_init(
        struct aws_log_writer *writer,
        struct aws_allocator *allocator,
        const char *file_name);

/*
 * Frees all resources used by a log writer with the exception of the base structure memory
 */
AWS_IO_API
int aws_log_writer_cleanup(struct aws_log_writer *writer);

#endif /* AWS_IO_LOG_WRITER_H */

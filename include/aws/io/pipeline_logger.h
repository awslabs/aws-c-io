
#ifndef AWS_IO_PIPELINE_LOGGER_H
#define AWS_IO_PIPELINE_LOGGER_H

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

#include <aws/io/logging.h>

struct aws_log_formatter;
struct aws_log_channel;
struct aws_allocator;

/*
 * Logger implementation composing the three components:
 *
 * The formatter takes var args input from the user and produces a formatted log line
 * The writer takes a formatted log line and outputs it somewhere
 * The channel is the transport between the two
 */
struct aws_pipeline_logger {
    struct aws_log_formatter *formatter;
    struct aws_log_channel *channel;
    struct aws_log_writer *writer;
    struct aws_allocator *allocator;
    enum aws_log_level level;
};

/*
 * Initializes a pipeline logger from components that have already been initialized.  This is not an ownership transfer.
 * After the pipeline logger is cleaned up, the components will have to manually be cleaned up by the user.
 */
AWS_IO_API
int aws_pipeline_logger_init_from_unowned_components(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_log_formatter *formatter,
    struct aws_log_channel *channel,
    struct aws_log_writer *writer,
    enum aws_log_level level);

/*
 * Initializes a pipeline logger that is built from the default formatter, a background thread-based channel, and
 * a file writer.  The default logger in almost all circumstances.
 */
AWS_IO_API
int aws_pipeline_logger_file_writer_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level,
    const char *file_name);

/*
 * Initializes a pipeline logger that is built from the default formatter, a background thread-based channel, and
 * a writer that outputs to stdout.
 */
AWS_IO_API
int aws_pipeline_logger_stdout_writer_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level);

/*
 * Initializes a pipeline logger that is built from the default formatter, a background thread-based channel, and
 * a writer that outputs to stderr.
 */
AWS_IO_API
int aws_pipeline_logger_stderr_writer_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level);

#endif /* AWS_IO_PIPELINE_LOGGER_H */

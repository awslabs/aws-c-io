#ifndef AWS_IO_LOGGING_H
#define AWS_IO_LOGGING_H

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

#include <aws/common/logging.h>

struct aws_log_channel;
struct aws_log_formatter;
struct aws_log_writer;

enum aws_io_log_subject {
    AWS_LS_IO_GENERAL = 0,
    AWS_LS_IO_EVENT_LOOP,
    AWS_LS_IO_SOCKET,
    AWS_LS_IO_SOCKET_HANDLER,
    AWS_LS_IO_TLS,
    AWS_LS_IO_ALPN,
    AWS_LS_IO_DNS,
    AWS_LS_IO_PKI,
    AWS_LS_IO_CHANNEL,
    AWS_LS_IO_CHANNEL_BOOTSTRAP,
    AWS_LS_IO_FILE_UTILS,
    AWS_LS_IO_SHARED_LIBRARY,
    AWS_IO_LS_LAST = (AWS_LS_IO_GENERAL + AWS_LOG_SUBJECT_SPACE_SIZE - 1)
};

/*
 * Standard logger implementation composing three sub-components:
 *
 * The formatter takes var args input from the user and produces a formatted log line
 * The writer takes a formatted log line and outputs it somewhere
 * The channel is the transport between the two
 */
struct aws_logger_pipeline {
    struct aws_log_formatter *formatter;
    struct aws_log_channel *channel;
    struct aws_log_writer *writer;
    struct aws_allocator *allocator;
    enum aws_log_level level;
};

/**
 * Options for aws_logger_init_standard().
 * Set `filename` to open a file for logging and close it when the logger cleans up.
 * Set `file` to use a file that is already open, such as `stderr` or `stdout`.
 */
struct aws_logger_standard_options {
    enum aws_log_level level;
    const char *filename;
    FILE *file;
};

AWS_EXTERN_C_BEGIN

/*
 * Initializes a pipeline logger that is built from the default formatter, a background thread-based channel, and
 * a file writer.  The default logger in almost all circumstances.
 */
AWS_IO_API
int aws_logger_init_standard(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_logger_standard_options *options);

/*
 * Initializes a pipeline logger from components that have already been initialized.  This is not an ownership transfer.
 * After the pipeline logger is cleaned up, the components will have to manually be cleaned up by the user.
 */
AWS_IO_API
int aws_logger_init_from_external(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_log_formatter *formatter,
    struct aws_log_channel *channel,
    struct aws_log_writer *writer,
    enum aws_log_level level);

/**
 * Load aws-c-io's log subject strings.
 */
AWS_IO_API
void aws_io_load_log_subject_strings(void);

/*
 * Pipeline logger vtable for custom configurations
 */
AWS_IO_API
extern struct aws_logger_vtable g_pipeline_logger_owned_vtable;

AWS_EXTERN_C_END

#endif /* AWS_IO_LOGGING_H */

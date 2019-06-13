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

#include <aws/io/logging.h>

#include <aws/common/string.h>

#include <aws/io/log_channel.h>
#include <aws/io/log_formatter.h>
#include <aws/io/log_writer.h>

#include <stdarg.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

static void s_aws_logger_pipeline_owned_clean_up(struct aws_logger *logger) {
    struct aws_logger_pipeline *impl = logger->p_impl;

    AWS_ASSERT(impl->channel->vtable->clean_up != NULL);
    (impl->channel->vtable->clean_up)(impl->channel);

    AWS_ASSERT(impl->formatter->vtable->clean_up != NULL);
    (impl->formatter->vtable->clean_up)(impl->formatter);

    AWS_ASSERT(impl->writer->vtable->clean_up != NULL);
    (impl->writer->vtable->clean_up)(impl->writer);

    aws_mem_release(impl->allocator, impl->channel);
    aws_mem_release(impl->allocator, impl->formatter);
    aws_mem_release(impl->allocator, impl->writer);

    aws_mem_release(impl->allocator, impl);
}

/*
 * Pipeline logger implementation
 */
static int s_aws_logger_pipeline_log(
    struct aws_logger *logger,
    enum aws_log_level log_level,
    aws_log_subject_t subject,
    const char *format,
    ...) {
    va_list format_args;
    va_start(format_args, format);

    struct aws_logger_pipeline *impl = logger->p_impl;
    struct aws_string *output = NULL;

    AWS_ASSERT(impl->formatter->vtable->format != NULL);
    int result = (impl->formatter->vtable->format)(impl->formatter, &output, log_level, subject, format, format_args);

    va_end(format_args);

    if (result != AWS_OP_SUCCESS || output == NULL) {
        return AWS_OP_ERR;
    }

    AWS_ASSERT(impl->channel->vtable->send != NULL);
    if ((impl->channel->vtable->send)(impl->channel, output)) {
        /*
         * failure to send implies failure to transfer ownership
         */
        aws_string_destroy(output);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static enum aws_log_level s_aws_logger_pipeline_get_log_level(struct aws_logger *logger, aws_log_subject_t subject) {
    (void)subject;

    struct aws_logger_pipeline *impl = logger->p_impl;

    return impl->level;
}

struct aws_logger_vtable g_pipeline_logger_owned_vtable = {
    .get_log_level = s_aws_logger_pipeline_get_log_level,
    .log = s_aws_logger_pipeline_log,
    .clean_up = s_aws_logger_pipeline_owned_clean_up,
};

int aws_logger_init_standard(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_logger_standard_options *options) {

    struct aws_logger_pipeline *impl = aws_mem_calloc(allocator, 1, sizeof(struct aws_logger_pipeline));
    if (impl == NULL) {
        return AWS_OP_ERR;
    }

    struct aws_log_writer *writer = aws_mem_acquire(allocator, sizeof(struct aws_log_writer));
    if (writer == NULL) {
        goto on_allocate_writer_failure;
    }

    struct aws_log_writer_file_options file_writer_options = {
        .filename = options->filename,
        .file = options->file,
    };

    if (aws_log_writer_init_file(writer, allocator, &file_writer_options)) {
        goto on_init_writer_failure;
    }

    struct aws_log_formatter *formatter = aws_mem_acquire(allocator, sizeof(struct aws_log_formatter));
    if (formatter == NULL) {
        goto on_allocate_formatter_failure;
    }

    struct aws_log_formatter_standard_options formatter_options = {.date_format = AWS_DATE_FORMAT_ISO_8601};

    if (aws_log_formatter_init_default(formatter, allocator, &formatter_options)) {
        goto on_init_formatter_failure;
    }

    struct aws_log_channel *channel = aws_mem_acquire(allocator, sizeof(struct aws_log_channel));
    if (channel == NULL) {
        goto on_allocate_channel_failure;
    }

    if (aws_log_channel_init_background(channel, allocator, writer) == AWS_OP_SUCCESS) {
        impl->formatter = formatter;
        impl->channel = channel;
        impl->writer = writer;
        impl->allocator = allocator;
        impl->level = options->level;

        logger->vtable = &g_pipeline_logger_owned_vtable;
        logger->allocator = allocator;
        logger->p_impl = impl;

        return AWS_OP_SUCCESS;
    }

    aws_mem_release(allocator, channel);

on_allocate_channel_failure:
    aws_log_formatter_clean_up(formatter);

on_init_formatter_failure:
    aws_mem_release(allocator, formatter);

on_allocate_formatter_failure:
    aws_log_writer_clean_up(writer);

on_init_writer_failure:
    aws_mem_release(allocator, writer);

on_allocate_writer_failure:
    aws_mem_release(allocator, impl);

    return AWS_OP_ERR;
}

/*
 * Pipeline logger implementation where all the components are externally owned.  No clean up
 * is done on the components.  Useful for tests where components are on the stack and often mocked.
 */
static void s_aws_pipeline_logger_unowned_clean_up(struct aws_logger *logger) {
    struct aws_logger_pipeline *impl = (struct aws_logger_pipeline *)logger->p_impl;

    aws_mem_release(impl->allocator, impl);
}

static struct aws_logger_vtable s_pipeline_logger_unowned_vtable = {
    .get_log_level = s_aws_logger_pipeline_get_log_level,
    .log = s_aws_logger_pipeline_log,
    .clean_up = s_aws_pipeline_logger_unowned_clean_up,
};

int aws_logger_init_from_external(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_log_formatter *formatter,
    struct aws_log_channel *channel,
    struct aws_log_writer *writer,
    enum aws_log_level level) {

    struct aws_logger_pipeline *impl = aws_mem_acquire(allocator, sizeof(struct aws_logger_pipeline));

    if (impl == NULL) {
        return AWS_OP_ERR;
    }

    impl->formatter = formatter;
    impl->channel = channel;
    impl->writer = writer;
    impl->allocator = allocator;
    impl->level = level;

    logger->vtable = &s_pipeline_logger_unowned_vtable;
    logger->allocator = allocator;
    logger->p_impl = impl;

    return AWS_OP_SUCCESS;
}

static struct aws_log_subject_info s_io_log_subject_infos[] = {
    DEFINE_LOG_SUBJECT_INFO(
        AWS_LS_IO_GENERAL,
        "aws-c-io",
        "Subject for IO logging that doesn't belong to any particular category"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_EVENT_LOOP, "event-loop", "Subject for Event-loop specific logging."),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_SOCKET, "socket", "Subject for Socket specific logging."),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_SOCKET_HANDLER, "socket-handler", "Subject for a socket channel handler."),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_TLS, "tls-handler", "Subject for TLS-related logging"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_ALPN, "alpn", "Subject for ALPN-related logging"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_DNS, "dns", "Subject for DNS-related logging"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_PKI, "pki-utils", "Subject for Pki utilities."),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_CHANNEL, "channel", "Subject for Channels"),
    DEFINE_LOG_SUBJECT_INFO(
        AWS_LS_IO_CHANNEL_BOOTSTRAP,
        "channel-bootstrap",
        "Subject for channel bootstrap (client and server modes)"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_FILE_UTILS, "file-utils", "Subject for file operations"),
    DEFINE_LOG_SUBJECT_INFO(AWS_LS_IO_SHARED_LIBRARY, "shared-library", "Subject for shared library operations"),
};

static struct aws_log_subject_info_list s_io_log_subject_list = {
    .subject_list = s_io_log_subject_infos,
    .count = AWS_ARRAY_SIZE(s_io_log_subject_infos),
};

void aws_io_load_log_subject_strings(void) {
    aws_register_log_subject_info_list(&s_io_log_subject_list);
}

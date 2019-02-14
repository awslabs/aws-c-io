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

#include <aws/io/pipeline_logger.h>

#include <aws/common/string.h>
#include <aws/io/log_channel.h>
#include <aws/io/log_formatter.h>
#include <aws/io/log_writer.h>

#include <stdio.h>

/*
 * Pipeline logger implementation
 */
static int s_pipeline_logger_log_fn(struct aws_logger *logger, enum aws_log_level log_level, aws_log_subject_t subject, const char *format, ...) {
    va_list format_args;
    va_start(format_args, format);

    struct aws_pipeline_logger *impl = (struct aws_pipeline_logger *)logger->p_impl;
    struct aws_string *output = NULL;

    int result = (*impl->formatter->vtable->format_fn)(impl->formatter, &output, log_level, subject, format, format_args);

    va_end(format_args);

    if (result != AWS_OP_SUCCESS || output == NULL) {
        return AWS_OP_ERR;
    }

    if ((*impl->channel->vtable->send_fn)(impl->channel, output)) {
        /*
         * failure to send implies failure to transfer ownership
         */
        aws_string_destroy(output);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static enum aws_log_level s_pipeline_logger_get_log_level_fn(struct aws_logger *logger, aws_log_subject_t subject) {
    (void)subject;

    struct aws_pipeline_logger *impl = (struct aws_pipeline_logger *)logger->p_impl;

    return impl->level;
}

static int s_pipeline_logger_unowned_cleanup_fn(struct aws_logger *logger) {
    struct aws_pipeline_logger *impl = (struct aws_pipeline_logger *)logger->p_impl;

    aws_mem_release(impl->allocator, impl);

    return AWS_OP_SUCCESS;
}

static struct aws_logger_vtable s_pipeline_logger_unowned_vtable = {
    .get_log_level_fn = s_pipeline_logger_get_log_level_fn,
    .log_fn = s_pipeline_logger_log_fn,
    .cleanup_fn = s_pipeline_logger_unowned_cleanup_fn
};

static int s_pipeline_logger_owned_cleanup_fn(struct aws_logger *logger) {
    struct aws_pipeline_logger *impl = (struct aws_pipeline_logger *)logger->p_impl;

    (*impl->channel->vtable->cleanup_fn)(impl->channel);
    (*impl->formatter->vtable->cleanup_fn)(impl->formatter);
    (*impl->writer->vtable->cleanup_fn)(impl->writer);

    aws_mem_release(impl->allocator, impl->channel);
    aws_mem_release(impl->allocator, impl->formatter);
    aws_mem_release(impl->allocator, impl->writer);

    aws_mem_release(impl->allocator, impl);

    return AWS_OP_SUCCESS;
}

static struct aws_logger_vtable s_pipeline_logger_owned_vtable = {
    .get_log_level_fn = s_pipeline_logger_get_log_level_fn,
    .log_fn = s_pipeline_logger_log_fn,
    .cleanup_fn = s_pipeline_logger_owned_cleanup_fn
};

int aws_pipeline_logger_init_from_unowned_components(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_log_formatter *formatter,
    struct aws_log_channel *channel,
    struct aws_log_writer *writer,
    enum aws_log_level level) {

    struct aws_pipeline_logger *impl = (struct aws_pipeline_logger *)aws_mem_acquire(allocator, sizeof(struct aws_pipeline_logger));
    if (impl == NULL) {
        return aws_raise_error(AWS_ERROR_OOM);
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

int s_aws_pipeline_logger_init_internal(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level,
    struct aws_log_writer *writer) {

    struct aws_pipeline_logger *impl = (struct aws_pipeline_logger *)aws_mem_acquire(allocator, sizeof(struct aws_pipeline_logger));
    if (impl == NULL) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    struct aws_log_formatter *formatter = (struct aws_log_formatter *)aws_mem_acquire(allocator, sizeof(struct aws_log_formatter));
    if (formatter == NULL) {
        aws_raise_error(AWS_ERROR_OOM);
        goto on_allocate_formatter_failure;
    }

    if (aws_default_log_formatter_init(formatter, allocator, AWS_DATE_FORMAT_ISO_8601)) {
        goto on_init_formatter_failure;
    }

    struct aws_log_channel *channel = (struct aws_log_channel *)aws_mem_acquire(allocator, sizeof(struct aws_log_channel));
    if (channel == NULL) {
        aws_raise_error(AWS_ERROR_OOM);
        goto on_allocate_channel_failure;
    }

    if (aws_foreground_log_channel_init(channel, allocator, writer) == AWS_OP_SUCCESS) {
        impl->formatter = formatter;
        impl->channel = channel;
        impl->writer = writer;
        impl->allocator = allocator;
        impl->level = level;

        logger->vtable = &s_pipeline_logger_owned_vtable;
        logger->allocator = allocator;
        logger->p_impl = impl;

        return AWS_OP_SUCCESS;
    }

    aws_mem_release(allocator, channel);

on_allocate_channel_failure:
    aws_log_formatter_cleanup(formatter);

on_init_formatter_failure:
    aws_mem_release(allocator, formatter);

on_allocate_formatter_failure:
    aws_mem_release(allocator, impl);

    return AWS_OP_ERR;
}

int aws_pipeline_logger_file_writer_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level,
    const char *file_name) {

    struct aws_log_writer *writer = (struct aws_log_writer *)aws_mem_acquire(allocator, sizeof(struct aws_log_writer));
    if (writer == NULL) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    if (aws_file_log_writer_init(writer, allocator, file_name)) {
        aws_mem_release(allocator, writer);
        return AWS_OP_ERR;
    }

    if (s_aws_pipeline_logger_init_internal(logger, allocator, level, writer)) {
        aws_log_writer_cleanup(writer);
        aws_mem_release(allocator, writer);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_pipeline_logger_stdout_writer_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level) {

    struct aws_log_writer *writer = (struct aws_log_writer *)aws_mem_acquire(allocator, sizeof(struct aws_log_writer));
    if (writer == NULL) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    if (aws_stdout_log_writer_init(writer, allocator)) {
        aws_mem_release(allocator, writer);
        return AWS_OP_ERR;
    }

    if (s_aws_pipeline_logger_init_internal(logger, allocator, level, writer)) {
        aws_log_writer_cleanup(writer);
        aws_mem_release(allocator, writer);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}


int aws_pipeline_logger_stderr_writer_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    enum aws_log_level level) {

    struct aws_log_writer *writer = (struct aws_log_writer *)aws_mem_acquire(allocator, sizeof(struct aws_log_writer));
    if (writer == NULL) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    if (aws_stderr_log_writer_init(writer, allocator)) {
        aws_mem_release(allocator, writer);
        return AWS_OP_ERR;
    }

    if (s_aws_pipeline_logger_init_internal(logger, allocator, level, writer)) {
        aws_log_writer_cleanup(writer);
        aws_mem_release(allocator, writer);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

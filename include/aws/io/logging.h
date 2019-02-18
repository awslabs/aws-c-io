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

#include <assert.h>

struct aws_log_channel;
struct aws_log_formatter;
struct aws_log_writer;

#define AWS_LOG_LEVEL_NONE 0
#define AWS_LOG_LEVEL_FATAL 1
#define AWS_LOG_LEVEL_ERROR 2
#define AWS_LOG_LEVEL_WARN 3
#define AWS_LOG_LEVEL_INFO 4
#define AWS_LOG_LEVEL_DEBUG 5
#define AWS_LOG_LEVEL_TRACE 6

/**
 * Controls what log calls pass through the logger and what log calls get filtered out.
 * If a log level has a value of X, then all log calls using a level <= X will appear, while
 * those using a value > X will not occur.
 *
 * You can filter both dynamically (by setting the log level on the logger object) or statically
 * (by defining AWS_STATIC_LOG_LEVEL to be an appropriate integer module-wide).  Statically filtered
 * log calls will be completely compiled out but require a rebuild if you want to get more detail
 * about what's happening.
 */
enum aws_log_level {
    AWS_LL_NONE = AWS_LOG_LEVEL_NONE,
    AWS_LL_FATAL = AWS_LOG_LEVEL_FATAL,
    AWS_LL_ERROR = AWS_LOG_LEVEL_ERROR,
    AWS_LL_WARN = AWS_LOG_LEVEL_WARN,
    AWS_LL_INFO = AWS_LOG_LEVEL_INFO,
    AWS_LL_DEBUG = AWS_LOG_LEVEL_DEBUG,
    AWS_LL_TRACE = AWS_LOG_LEVEL_TRACE,

    AWS_LL_COUNT
};

/**
 * Log subject is a to-be-defined key, independent of level, that will allow for additional filtering options.
 *
 * The general idea is to support the logging of related functionality and allow for level control with a
 * finer-grained approach.
 *
 * For example, enable TRACE logging for mqtt-related log statements, but only WARN logging everywhere else.
 */
typedef uint32_t aws_log_subject_t;

#define AWS_LOG_SUBJECT_NONE ((aws_log_subject_t)0)

struct aws_logger;

/**
 * We separate the log level function from the log call itself so that we can do the filter check in the macros (see below)
 *
 * By doing so, we make it so that the variadic format arguments are not even evaluated if the filter check does not succeed.
 */
struct aws_logger_vtable {
    int(* const log)(struct aws_logger *logger, enum aws_log_level log_level, aws_log_subject_t subject, const char *format, ...);
    enum aws_log_level(* const get_log_level)(struct aws_logger *logger, aws_log_subject_t subject);
    int(* const cleanup)(struct aws_logger *logger);
};

struct aws_logger {
    struct aws_logger_vtable *vtable;
    struct aws_allocator *allocator;
    void *p_impl;
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

struct aws_logger_standard_options {
    enum aws_log_level level;
    const char *filename;
};

/**
 * The base formatted logging macro that all other formatted logging macros resolve to.
 * Checks for a logger and filters based on log level.
 *
 */
#define AWS_LOGF_RAW(log_level, subject, ...)                                                                   \
{                                                                                                               \
    assert(log_level > 0);                                                                                      \
    struct aws_logger *logger = aws_logger_get();                                                               \
    if (logger != NULL && logger->vtable->get_log_level(logger, subject) >= log_level) {                        \
        logger->vtable->log(logger, log_level, subject, __VA_ARGS__);                                           \
    }                                                                                                           \
}

#define AWS_LOGF(log_level, ...) AWS_LOGF_RAW(log_level, AWS_LOG_SUBJECT_NONE, __VA_ARGS__)

/**
 * LOGF_<level> variants for each level.  These are what should be used directly to do all logging.
 *
 * i.e.
 *
 * LOGF_FATAL("Device \"%s\" not found", device->name);
 *
 *
 * Later we will likely expose Subject-aware variants
 */
#if !defined(AWS_STATIC_LOG_LEVEL) || (AWS_STATIC_LOG_LEVEL >= AWS_LOG_LEVEL_FATAL)
#   define AWS_LOGF_FATAL(...) AWS_LOGF(AWS_LL_FATAL, __VA_ARGS__)
#else
#   define AWS_LOGF_FATAL(...)
#endif

#if !defined(AWS_STATIC_LOG_LEVEL) || (AWS_STATIC_LOG_LEVEL >= AWS_LOG_LEVEL_ERROR)
#   define AWS_LOGF_ERROR(...) AWS_LOGF(AWS_LL_ERROR, __VA_ARGS__)
#else
#   define AWS_LOGF_ERROR(...)
#endif

#if !defined(AWS_STATIC_LOG_LEVEL) || (AWS_STATIC_LOG_LEVEL >= AWS_LOG_LEVEL_WARN)
#   define AWS_LOGF_WARN(...) AWS_LOGF(AWS_LL_WARN, __VA_ARGS__)
#else
#   define AWS_LOGF_WARN(...)
#endif

#if !defined(AWS_STATIC_LOG_LEVEL) || (AWS_STATIC_LOG_LEVEL >= AWS_LOG_LEVEL_INFO)
#   define AWS_LOGF_INFO(...) AWS_LOGF(AWS_LL_INFO, __VA_ARGS__)
#else
#   define AWS_LOGF_INFO(...)
#endif

#if !defined(AWS_STATIC_LOG_LEVEL) || (AWS_STATIC_LOG_LEVEL >= AWS_LOG_LEVEL_DEBUG)
#   define AWS_LOGF_DEBUG(...) AWS_LOGF(AWS_LL_DEBUG, __VA_ARGS__)
#else
#   define AWS_LOGF_DEBUG(...)
#endif

#if !defined(AWS_STATIC_LOG_LEVEL) || (AWS_STATIC_LOG_LEVEL >= AWS_LOG_LEVEL_TRACE)
#   define AWS_LOGF_TRACE(...) AWS_LOGF(AWS_LL_TRACE, __VA_ARGS__)
#else
#   define AWS_LOGF_TRACE(...)
#endif


AWS_EXTERN_C_BEGIN

/**
 * Sets the aws logger used globally across the process.  Not thread-safe.  Must only be called once.
 */
AWS_IO_API
void aws_logger_set(struct aws_logger *logger);

/**
 * Gets the aws logger used globally across the process.
 */
AWS_IO_API
struct aws_logger *aws_logger_get(void);

/**
 * Cleans up all resources used by the logger; simply invokes the cleanup v-function
 */
AWS_IO_API
int aws_logger_cleanup(struct aws_logger *logger);

/**
 * Converts a log level to a c-string constant.  Intended primarily to support building log lines that
 * include the level in them, i.e.
 *
 * [ERROR] 10:34:54.642 01-31-19 - Json parse error....
 */
AWS_IO_API
int aws_log_level_to_string(enum aws_log_level log_level, const char **level_string);

/*
 * Initializes a pipeline logger that is built from the default formatter, a background thread-based channel, and
 * a file writer.  The default logger in almost all circumstances.
 */
AWS_IO_API
int aws_logger_standard_init(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_logger_standard_options *options);

/*
 * Initializes a pipeline logger from components that have already been initialized.  This is not an ownership transfer.
 * After the pipeline logger is cleaned up, the components will have to manually be cleaned up by the user.
 */
AWS_IO_API
int aws_logger_pipeline_init_external(
    struct aws_logger *logger,
    struct aws_allocator *allocator,
    struct aws_log_formatter *formatter,
    struct aws_log_channel *channel,
    struct aws_log_writer *writer,
    enum aws_log_level level);

/*
 * Pipeline logger vtable for custom configurations
 */
AWS_IO_API
extern struct aws_logger_vtable g_pipeline_logger_owned_vtable;

AWS_EXTERN_C_END

#endif /* AWS_IO_LOGGING_H */

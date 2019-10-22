#ifndef AWS_IO_STATISTICS_H
#define AWS_IO_STATISTICS_H

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

#include <aws/common/statistics.h>

enum aws_crt_io_statistics_category {
    AWSCRT_STAT_CAT_SOCKET = AWS_CRT_STATISTICS_CATEGORY_BEGIN_RANGE(AWS_C_IO_PACKAGE_ID),
    AWSCRT_STAT_CAT_TLS
};

/**
 * Socket channel handler statistics record
 */
struct aws_crt_statistics_socket {
    aws_crt_statistics_category_t category;
    uint64_t bytes_read;
    uint64_t bytes_written;
};

/**
 * An enum for the current state of tls negotiation within a tls channel handler
 */
enum aws_tls_negotiation_status {
    AWS_MTLS_STATUS_NONE,
    AWS_MTLS_STATUS_ONGOING,
    AWS_MTLS_STATUS_SUCCESS,
    AWS_MTLS_STATUS_FAILURE
};

/**
 * Tls channel handler statistics record
 */
struct aws_crt_statistics_tls {
    aws_crt_statistics_category_t category;
    uint64_t handshake_start_ms;
    enum aws_tls_negotiation_status handshake_status;
};

/**
 * Options configuring the behavior of the tls monitor statistics handler
 *
 * tls_timeout_ms - time, in ms, for tls negotitation to succeed before the monitor shuts down the channel
 */
struct aws_tls_monitor_options {
    uint32_t tls_timeout_ms;
};

AWS_EXTERN_C_BEGIN

/* Statistics handlers */

/**
 * Creates a new statistics handler that wraps a set (chain) of statistics handlers.  The new handler's
 * process_statistics function calls the process_statistics function of each handler in the chain.  The new handler's
 * report interval is the minimum of the report intervals of all handlers in the chain.
 *
 * The new handler's destroy calls destroy on all handlers in the chain.
 */
AWS_IO_API
struct aws_crt_statistics_handler *aws_statistics_handler_new_chain(
    struct aws_allocator *allocator,
    struct aws_crt_statistics_handler **handlers,
    size_t handler_count);

/**
 * Creates a new statistics handler that monitors the status of any tls channel handlers in the channel and shuts
 * down the channel if tls negotiation takes longer than a configurable timeout value.
 */
AWS_IO_API
struct aws_crt_statistics_handler *aws_crt_statistics_handler_new_tls_monitor(
    struct aws_allocator *allocator,
    struct aws_tls_monitor_options *options);

/* Statistics objects */

/**
 *
 */
AWS_IO_API
int aws_crt_statistics_socket_init(struct aws_crt_statistics_socket *stats);

/**
 *
 */
AWS_IO_API
void aws_crt_statistics_socket_cleanup(struct aws_crt_statistics_socket *stats);

/**
 *
 */
AWS_IO_API
void aws_crt_statistics_socket_reset(struct aws_crt_statistics_socket *stats);

/**
 *
 */
AWS_IO_API
int aws_crt_statistics_tls_init(struct aws_crt_statistics_tls *stats);

/**
 *
 */
AWS_IO_API
void aws_crt_statistics_tls_cleanup(struct aws_crt_statistics_tls *stats);

/**
 *
 */
AWS_IO_API
void aws_crt_statistics_tls_reset(struct aws_crt_statistics_tls *stats);

AWS_EXTERN_C_END

#endif /* AWS_IO_STATISTICS_H */

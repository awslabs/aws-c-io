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
    AWS_LS_IO_GENERAL = 0x0400,
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

#endif /* AWS_IO_LOGGING_H */

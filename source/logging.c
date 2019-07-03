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

/*
 * IO logging subjects
 */
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

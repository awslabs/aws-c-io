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

#include <aws/io/statistics.h>


int aws_statistics_set_socket_init(struct aws_statistics_set_socket *stats) {
    AWS_ZERO_STRUCT(*stats);
    stats->category = AWS_IO_STAT_CAT_SOCKET;

    return AWS_OP_SUCCESS;
}

void aws_statistics_set_socket_cleanup(struct aws_statistics_set_socket *stats) {}

void aws_statistics_set_socket_reset(struct aws_statistics_set_socket *stats) {
    stats->bytes_read = 0;
    stats->bytes_written = 0;
}

int aws_statistics_set_tls_init(struct aws_statistics_set_tls *stats) {
    AWS_ZERO_STRUCT(*stats);
    stats->category = AWS_IO_STAT_CAT_TLS;

    return AWS_OP_SUCCESS;
}

void aws_statistics_set_tls_cleanup(struct aws_statistics_set_tls *stats) {}

void aws_statistics_set_tls_reset(struct aws_statistics_set_tls *stats) {}
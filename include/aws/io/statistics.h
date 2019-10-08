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

enum aws_io_statistics_category_type {
    AWS_IO_STAT_CAT_SOCKET = AWS_C_IO_PACKAGE_ID * AWS_STATISTICS_CATEGORY_TYPE_STRIDE,
    AWS_IO_STAT_CAT_TLS
};

struct aws_statistics_set_socket {
    aws_statistics_category_t category;
    uint64_t bytes_read;
    uint64_t bytes_written;
};

struct aws_statistics_set_tls {
    aws_statistics_category_t category;
    bool handshake_complete;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API
int aws_statistics_set_socket_init(struct aws_statistics_set_socket *stats);

AWS_IO_API
void aws_statistics_set_socket_cleanup(struct aws_statistics_set_socket *stats);

AWS_IO_API
void aws_statistics_set_socket_reset(struct aws_statistics_set_socket *stats);

AWS_IO_API
int aws_statistics_set_tls_init(struct aws_statistics_set_tls *stats);

AWS_IO_API
void aws_statistics_set_tls_cleanup(struct aws_statistics_set_tls *stats);

AWS_IO_API
void aws_statistics_set_tls_reset(struct aws_statistics_set_tls *stats);

AWS_EXTERN_C_END

#endif /* AWS_IO_STATISTICS_H */

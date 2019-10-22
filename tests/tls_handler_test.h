#ifndef TLS_HANDLER_TEST_H
#define TLS_HANDLER_TEST_H

/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/io/tls_channel_handler.h>

/* common structure for tls options */
struct tls_opt_tester {
    struct aws_tls_ctx_options ctx_options;
    struct aws_tls_ctx *ctx;
    struct aws_tls_connection_options opt;
};

int tls_server_opt_tester_init(struct aws_allocator *allocator, struct tls_opt_tester *tester);

int tls_client_opt_tester_init(
    struct aws_allocator *allocator,
    struct tls_opt_tester *tester,
    struct aws_byte_cursor server_name);

int tls_opt_tester_clean_up(struct tls_opt_tester *tester);

#endif /* TLS_HANDLER_TEST_H */
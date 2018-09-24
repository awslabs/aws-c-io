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
#include <aws/io/tls_channel_handler.h>

#include <aws/io/channel.h>
#include <aws/io/pki_utils.h>

#include <aws/common/task_scheduler.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static const size_t EST_TLS_RECORD_OVERHEAD = 53; /* 5 byte header + 32 + 16 bytes for padding */


void aws_tls_init_static_state(struct aws_allocator *alloc) {
    (void)alloc;
}

void aws_tls_clean_up_tl_state(void) {
}

void aws_tls_clean_up_static_state(void) {
}

bool aws_tls_is_alpn_available(void) {
    return true;
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    (void)handler;
    return AWS_OP_ERR;
}


struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    (void)handler;
    struct aws_byte_buf ret_val;
    AWS_ZERO_STRUCT(ret_val);
    return ret_val;
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    (void)handler;
    struct aws_byte_buf ret_val;
    AWS_ZERO_STRUCT(ret_val);
    return ret_val;
}

struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    (void)allocator;
    (void)ctx;
    (void)options;
    (void)slot;
    return NULL;
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    (void)allocator;
    (void)ctx;
    (void)options;
    (void)slot;
    return NULL;
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    (void)ctx;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    (void)alloc;
    (void)options;
    return NULL;
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    (void)alloc;
    (void)options;
    return NULL;
}

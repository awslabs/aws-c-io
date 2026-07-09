/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_L4PROXY_IMPL_H
#define AWS_IO_L4PROXY_IMPL_H

#include <aws/io/io.h>

#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/channel.h>

#include <stdint.h>

struct aws_l4_proxy_config;
struct aws_l4_proxy_channel_handler;

struct aws_connection_remote {
    struct aws_byte_cursor host;
    uint32_t port;
};

struct aws_l4_proxy_channel_handler_options {

    struct aws_connection_remote *remote;

    void (*negotiation_complete_callback)(int, void *);
    void *negotiation_complete_user_data;
};

struct aws_l4_proxy_config_vtable {
    struct aws_l4_proxy_channel_handler *(*new_channel_handler)(struct aws_l4_proxy_config *, struct aws_l4_proxy_channel_handler_options *);
};

struct aws_l4_proxy_config {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    struct aws_l4_proxy_config_vtable *vtable;
    void *impl;

    struct aws_byte_buf proxy_host;
    uint16_t proxy_port;

    uint32_t negotiation_timeout_ms;
};

enum aws_l4_proxy_protocol_status {
    AWS_L4PPS_IN_PROGRESS,
    AWS_L4PPS_SUCCESS,
    AWS_L4PPS_FAILURE,
};

/*
 * Input-output structure containing the results of an attempt to progress the auth negotiation
 */
struct aws_l4_proxy_negotiation_context {

    /* Incoming data to be processed.  Negotiation instance will update this based on bytes consumed */
    struct aws_byte_cursor *data;

    /* Resulting current status of the negotiation */
    enum aws_l4_proxy_protocol_status status;

    /* Data to write to the socket as part of the negotiation.  Caller must always initialize this. */
    struct aws_byte_buf *to_write;

    /* if the negotiation failed, this has the error code in it */
    int error_code;
};

struct aws_l4_proxy_channel_handler_vtable {
    int (*start_negotiation)(struct aws_l4_proxy_channel_handler *);
};

struct aws_l4_proxy_channel_handler {
    struct aws_allocator *allocator;

    struct aws_l4_proxy_channel_handler_vtable *vtable;
    void *impl;

    struct aws_channel_handler channel_handler;

    struct aws_l4_proxy_config *config;

    struct aws_byte_buf remote_host;
    uint32_t remote_port;

    void (*negotiation_complete_callback)(int, void *);
    void *negotiation_complete_user_data;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API void aws_l4_proxy_config_clean_up(struct aws_l4_proxy_config *config);

AWS_IO_API int aws_l4_proxy_channel_handler_start_negotiation(struct aws_l4_proxy_channel_handler *handler);

AWS_IO_API void aws_l4_proxy_channel_handler_clean_up(struct aws_l4_proxy_channel_handler *handler);

AWS_EXTERN_C_END

#endif /* AWS_IO_L4PROXY_IMPL_H */

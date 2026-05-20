/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_SOCKS5_IMPL_H
#define AWS_IO_SOCKS5_IMPL_H

#include <aws/io/io.h>

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/socks5.h>

#include <stdint.h>

#define METHOD_SELECTION_LENGTH 2
#define METHOD_RESPONSE_LENGTH 2
#define SOCKS_VERSION 5
#define NO_ACCEPTABLE_METHODS_ID 255

struct aws_socks5_proxy_config {
    struct aws_allocator *allocator;

    struct aws_ref_count ref_count;

    struct aws_byte_buf proxy_host;
    uint16_t proxy_port;

    struct aws_socks5_proxy_negotiation_strategy *negotiation_strategy;

    uint32_t negotiation_timeout_ms;
};

enum aws_socks5_protocol_status {
    AWS_S5PS_IN_PROGRESS,
    AWS_S5PS_SUCCESS,
    AWS_S5PS_FAILURE,
};

/*
 * Input-output structure containing the results of an attempt to progress the auth negotiation
 */
struct aws_socks5_negotiation_context {

    /* Incoming data to be processed.  Negotiation instance will update this based on bytes consumed */
    struct aws_byte_cursor *data;

    /* Resulting current status of the negotiation */
    enum aws_socks5_protocol_status status;

    /* Data to write to the socket as part of the negotiation.  Caller must always initialize this. */
    struct aws_byte_buf *to_write;

    /* if the negotiation failed, this has the error code in it */
    int error_code;
};

struct aws_socks5_proxy_negotiation_strategy_instance;

struct aws_socks5_proxy_negotiation_strategy_instance_vtable {
    void (*destroy)(struct aws_socks5_proxy_negotiation_strategy_instance *);
    void (*drive_negotiation)(
        struct aws_socks5_proxy_negotiation_strategy_instance *,
        struct aws_socks5_negotiation_context *);

    /*
     * By keeping this separate from drive_negotiation we make it possible to compose strategies.  In particular,
     * if filling out the "client hello" was the responsibility of the strategy, then you could not take multiple
     * strategy instances and get a "client hello" that included multiple auth methods.
     */
    int (*get_auth_methods)(struct aws_socks5_proxy_negotiation_strategy_instance *, struct aws_array_list *);

    /*
     * Supporting transformative authentication methods would require additional methods for encoding and decoding
     * the data stream.  Ideally, the API should support trivial (no-copy) pass-through for io messages so that
     * the common case (no/basic auth) does not incur a performance hit.
     *
     * We don't commit to that yet since it's unlikely we'll ever support methods that require it.
     */
};

struct aws_socks5_proxy_negotiation_strategy_instance {
    struct aws_allocator *allocator;
    const struct aws_socks5_proxy_negotiation_strategy_instance_vtable *vtable;
    void *impl;
};

struct aws_socks5_proxy_negotiation_strategy_vtable {
    struct aws_socks5_proxy_negotiation_strategy_instance *(*new_instance)(
        struct aws_socks5_proxy_negotiation_strategy *);
};

struct aws_socks5_proxy_negotiation_strategy {
    struct aws_allocator *allocator;
    const struct aws_socks5_proxy_negotiation_strategy_vtable *vtable;
    struct aws_ref_count ref_count;
    void *impl;
};

struct aws_socks5_proxy_impl;

AWS_EXTERN_C_BEGIN

AWS_IO_API void aws_socks5_proxy_negotiation_strategy_instance_destroy(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance);

AWS_IO_API void aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_socks5_negotiation_context *context);

AWS_IO_API int aws_socks5_proxy_negotiation_strategy_instance_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *method);

AWS_IO_API struct aws_socks5_proxy_negotiation_strategy_instance *aws_socks5_proxy_negotiation_strategy_new_instance(
    struct aws_socks5_proxy_negotiation_strategy *strategy);

AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_no_auth(
    struct aws_allocator *allocator);

AWS_IO_API struct aws_socks5_proxy_impl *aws_socks5_proxy_impl_new(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_config *config);

AWS_IO_API void aws_socks5_proxy_impl_destroy(struct aws_socks5_proxy_impl *impl);

AWS_IO_API void aws_socks5_proxy_impl_drive_negotiation(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context);

AWS_EXTERN_C_END

#endif /* AWS_IO_SOCKS5_IMPL_H */

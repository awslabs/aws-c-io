#ifndef AWS_IO_TLS_HANDLER_H_
#define AWS_IO_TLS_HANDLER_H_
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

#include <aws/io/channel_handler.h>

typedef enum aws_tls_versions {
    AWS_IO_SSLv2 = 0x01,
    AWS_IO_SSLv3 = 0x02,
    AWS_IO_TLSv1 = 0x04,
    AWS_IO_TLSv1_1 = 0x08,
    AWS_IO_TLSv1_2 = 0x10,
    AWS_IO_TLSv1_3 = 0x20
} aws_tls_versions;

struct aws_tls_client_options {
    int8_t verify_peer;
    aws_tls_versions version_blacklist;
    const char *ca_file;
    const char *ca_path;
    const char *alpn_list;
    const char *server_name;
};

struct aws_tls_server_options {
    aws_tls_versions version_blacklist;
    const char *certificate_path;
    const char *private_key_path;
    const char *alpn_list;
};

struct aws_tls_ctx {
    struct aws_allocator *alloc;
};

struct aws_tls_channel_handler;

typedef uint8_t(*aws_verify_host_fn)(struct aws_tls_channel_handler *handler, const char *host_name, size_t host_name_len, void *ctx);
typedef void(*aws_on_negotiation_result)(struct aws_tls_channel_handler *handler, struct aws_channel *channel, int err_code, void *ctx);
typedef void(*aws_tls_on_data_read)(struct aws_tls_channel_handler *handler, const uint8_t *buf, size_t size, void *ctx);
typedef void(*aws_tls_on_error)(struct aws_tls_channel_handler *handler, int err, const char *message);


struct aws_tls_channel_handler {
    struct aws_channel_handler base;
    aws_tls_on_data_read on_read;
    void *read_ctx;
    aws_tls_on_error on_error;
    void *error_ctx;
    aws_on_negotiation_result on_negotiation;
    aws_verify_host_fn verify_host;
    void *negotiation_ctx;
    int8_t negotiation_finished;
    const char *server_name;
    const char *protocol;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API void aws_tls_init_static_state(struct aws_allocator *alloc);
AWS_IO_API void aws_tls_clean_up_static_state(struct aws_allocator *alloc);

AWS_IO_API struct aws_tls_channel_handler *aws_tls_client_handler_new(struct aws_tls_ctx *ctx, const char *server_name,
                         aws_on_negotiation_result on_negotiation, aws_verify_host_fn verify_host_fn, void *negotiation_ctx_data );

AWS_IO_API int aws_tls_client_handler_start_negotiation(struct aws_tls_channel_handler *handler, struct aws_channel *channel);

AWS_IO_API void aws_tls_set_on_read_cb(struct aws_tls_channel_handler *handler, aws_tls_on_data_read on_read, void *read_ctx_data);
AWS_IO_API void aws_tls_set_on_error_cb(struct aws_tls_channel_handler *handler, aws_tls_on_error on_read, void *error_ctx_data);

AWS_IO_API struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc,
                                                      struct aws_tls_server_options *options);

AWS_IO_API struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc,
                                                      struct aws_tls_client_options *options);

AWS_IO_API void  aws_tls_ctx_destroy(struct aws_tls_ctx *ctx);
AWS_IO_API struct aws_tls_channel_handler *aws_tls_server_handler_new(struct aws_tls_ctx *ctx,
                         aws_on_negotiation_result on_negotiation, aws_verify_host_fn verify_host_fn, void *negotiation_ctx_data);


AWS_IO_API int aws_tls_handler_write(struct aws_tls_channel_handler *handler, const uint8_t *to_write, size_t size);

#ifdef __cplusplus
}
#endif

static inline const char *aws_tls_handler_protocol(struct aws_tls_channel_handler *handler) {
    return handler->protocol;
}

static inline const char *aws_tls_handler_server_name(struct aws_tls_channel_handler *handler) {
    return handler->server_name;
}


#endif //AWS_IO_TLS_HANDLER_H_

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/socks5.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/logging.h>
#include <aws/io/private/socks5_impl.h>

static void s_aws_socks5_proxy_config_destroy(void *value) {
    struct aws_socks5_proxy_config *config = value;
    if (!config) {
        return;
    }

    aws_byte_buf_clean_up(&config->proxy_host);
    aws_socks5_proxy_negotiation_strategy_release(config->negotiation_strategy);

    aws_mem_release(config->allocator, config);
}

struct aws_socks5_proxy_config *aws_socks5_proxy_config_new(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_options *options) {

    struct aws_socks5_proxy_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_config));
    config->allocator = allocator;
    config->proxy_port = options->proxy_port;

    /* ensure we always have a strategy */
    if (options->negotiation_strategy) {
        config->negotiation_strategy = aws_socks5_proxy_negotiation_strategy_acquire(options->negotiation_strategy);
    } else {
        config->negotiation_strategy = aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);
    }

    config->negotiation_timeout_ms = options->negotiation_timeout_ms;

    aws_byte_buf_init_copy_from_cursor(&config->proxy_host, allocator, options->proxy_host);

    aws_ref_count_init(&config->ref_count, config, s_aws_socks5_proxy_config_destroy);

    return config;
}

struct aws_socks5_proxy_config *aws_socks5_proxy_config_release(struct aws_socks5_proxy_config *config) {
    if (config) {
        aws_ref_count_release(&config->ref_count);
    }

    return NULL;
}

struct aws_socks5_proxy_config *aws_socks5_proxy_config_acquire(struct aws_socks5_proxy_config *config) {
    if (config) {
        aws_ref_count_acquire(&config->ref_count);
    }

    return config;
}

// general negotiation strategy

struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_acquire(
    struct aws_socks5_proxy_negotiation_strategy *strategy) {
    if (strategy != NULL) {
        aws_ref_count_acquire(&strategy->ref_count);
    }

    return strategy;
}

struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_release(
    struct aws_socks5_proxy_negotiation_strategy *strategy) {
    if (strategy != NULL) {
        aws_ref_count_release(&strategy->ref_count);
    }

    return NULL;
}

struct aws_socks5_proxy_negotiation_strategy_instance *aws_socks5_proxy_negotiation_strategy_new_instance(
    struct aws_socks5_proxy_negotiation_strategy *strategy) {
    return strategy->vtable->new_instance(strategy);
}

void aws_socks5_proxy_negotiation_strategy_instance_destroy(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance) {
    if (instance != NULL) {
        instance->vtable->destroy(instance);
    }
}

void aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_socks5_negotiation_context *context) {
    instance->vtable->drive_negotiation(instance, context);
}

int aws_socks5_proxy_negotiation_strategy_instance_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    return instance->vtable->get_auth_methods(instance, methods);
}

/* Overall protocol implementation */

enum aws_socks5_proxy_impl_state {
    AWS_S5PIS_INVALID = -1,
    AWS_S5PIS_START = 0,
    AWS_S5PIS_PENDING_METHOD_REQUEST,
    AWS_S5PIS_PENDING_AUTH_SUBNEGOTIATION,
    AWS_S5PIS_PENDING_REQUEST,
    AWS_S5PIS_PENDING_RESPONSE,
    AWS_S5PIS_SUCCESS,
    AWS_S5PIS_FAILURE,

    AWS_S5PIS_COUNT,
};

static const char *s_aws_socks5_impl_state_strings[AWS_S5PIS_COUNT] = {
    "Start",
    "PendingMethodRequest",
    "PendingAuthSubnegotiation",
    "PendingRequest",
    "PendingResponse",
    "Success",
    "Failure",
};

struct aws_socks5_proxy_impl {
    struct aws_allocator *allocator;

    struct aws_socks5_proxy_config *config;
    struct aws_socks5_proxy_negotiation_strategy_instance *auth_instance;

    enum aws_socks5_proxy_impl_state state;

    struct aws_byte_buf write_buffer;
    struct aws_byte_cursor pending_write_data;

    struct aws_byte_buf read_buffer;

    int final_error_code;
};

void aws_socks5_proxy_impl_destroy(struct aws_socks5_proxy_impl *impl) {
    if (impl == NULL) {
        return;
    }

    aws_socks5_proxy_negotiation_strategy_instance_destroy(impl->auth_instance);

    aws_byte_buf_clean_up(&impl->write_buffer);
    aws_byte_buf_clean_up(&impl->read_buffer);

    aws_socks5_proxy_config_release(impl->config);

    aws_mem_release(impl->allocator, impl);
}

static const size_t DEFAULT_SOCKS5_PROTOCOL_BUFFER_SIZE = 512;

struct aws_socks5_proxy_impl *aws_socks5_proxy_impl_new(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_config *config) {

    if (allocator == NULL || config == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_socks5_proxy_impl *impl = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_impl));
    impl->allocator = allocator;
    impl->config = aws_socks5_proxy_config_acquire(config);
    impl->auth_instance = aws_socks5_proxy_negotiation_strategy_new_instance(config->negotiation_strategy);
    impl->state = AWS_S5PIS_START;
    if (aws_byte_buf_init(&impl->write_buffer, allocator, DEFAULT_SOCKS5_PROTOCOL_BUFFER_SIZE) ||
        aws_byte_buf_init(&impl->read_buffer, allocator, DEFAULT_SOCKS5_PROTOCOL_BUFFER_SIZE)) {
        goto failure;
    }

    return impl;

failure:

    aws_socks5_proxy_impl_destroy(impl);

    return NULL;
}

static void s_on_socks5_protocol_error(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context,
    int error_code) {
    context->error_code = error_code;
    impl->final_error_code = error_code;

    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKS5,
        "(%p) Socks5 proxy protocol negotiation failed with error code %d(%s)",
        (void *)impl,
        error_code,
        aws_error_debug_str(error_code));
}

static void s_transition_socks5_impl_state(
    struct aws_socks5_proxy_impl *impl,
    enum aws_socks5_proxy_impl_state new_state) {
    if (new_state != impl->state) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "(%p) Changing socks5 impl state from %d(%s) to %d(%s)",
            (void *)impl,
            (int)impl->state,
            s_aws_socks5_impl_state_strings[impl->state],
            (int)new_state,
            s_aws_socks5_impl_state_strings[new_state]);

        impl->state = new_state;
    }
}

static const uint8_t SOCKS5_VERSION_BYTE = 0x05;

static const uint8_t SOCKS_COMMAND_TYPE_CONNECT = 0x01;
static const uint8_t SOCKS_COMMAND_RESERVED_VALUE = 0x00;

enum aws_socks5_address_type {
    AWS_SOCKS5_ADDRESS_TYPE_IPV4 = 0x01,
    AWS_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME = 0x03,
    AWS_SOCKS5_ADDRESS_TYPE_IPV6 = 0x04,
};

// In order to know how many bytes we really need, we need to have received:
// Version (1 byte) + Reply (1 byte) + Reserved (1 byte) + Address Type (1 byte) +
//   1st byte of address field (for variable length if domain name)
static const size_t MINIMUM_RESPONSE_BYTES_REQUIRED = 5;

static const size_t SOCKS_RESPONSE_LENGTH_IPV4 = 10;             // 4 prefix bytes + 4 address bytes + 2 port bytes
static const size_t SOCKS_RESPONSE_LENGTH_IPV6 = 22;             // 4 prefix bytes + 16 address bytes + 2 port bytes
static const size_t SOCKS_RESPONSE_LENGTH_DOMAIN_NAME_FIXED = 7; // 4 prefix bytes + 1 length bytes + 2 port bytes

static const size_t SOCKS_RESPONSE_ADDRESS_TYPE_INDEX = 3;
static const size_t SOCKS_RESPONSE_REPLY_CODE_INDEX = 1;

static void s_handle_socks5_impl_state_start(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {

    struct aws_array_list methods;
    aws_array_list_init_dynamic(&methods, impl->allocator, 1, sizeof(uint8_t));

    aws_socks5_proxy_negotiation_strategy_instance_get_auth_methods(impl->auth_instance, &methods);
    size_t num_methods = aws_array_list_length(&methods);
    if (num_methods == 0 || num_methods > UINT8_MAX) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, "(%p) Illegal number of authentication methods: %d", (void *)impl, (int)num_methods);
        s_on_socks5_protocol_error(impl, context, AWS_IO_SOCKS5_INTERNAL_FAILURE);
        s_transition_socks5_impl_state(impl, AWS_S5PIS_FAILURE);
        goto done;
    }

    // failure is a crash
    aws_byte_buf_reserve(&impl->write_buffer, 2 + num_methods);

    aws_byte_buf_write_u8(&impl->write_buffer, SOCKS5_VERSION_BYTE);
    aws_byte_buf_write_u8(&impl->write_buffer, (uint8_t)num_methods);
    for (size_t i = 0; i < num_methods; ++i) {
        uint8_t method_byte = 0xFF;
        aws_array_list_get_at(&methods, &method_byte, i);
        aws_byte_buf_write_u8(&impl->write_buffer, method_byte);
    }

    impl->pending_write_data = aws_byte_cursor_from_buf(&impl->write_buffer);

    s_transition_socks5_impl_state(impl, AWS_S5PIS_PENDING_METHOD_REQUEST);

done:

    aws_array_list_clean_up(&methods);
}

static void s_handle_socks5_impl_state_pending_method_request(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {

    size_t write_length =
        aws_min_size(context->to_write->capacity - context->to_write->len, impl->pending_write_data.len);
    if (write_length > 0) {
        struct aws_byte_cursor to_copy = aws_byte_cursor_advance(&impl->pending_write_data, write_length);
        aws_byte_buf_append(context->to_write, &to_copy);
    }

    if (impl->pending_write_data.len == 0) {
        s_transition_socks5_impl_state(impl, AWS_S5PIS_PENDING_AUTH_SUBNEGOTIATION);
    }
}

static void s_build_connect_request(struct aws_socks5_proxy_impl *impl) {
    aws_byte_buf_reset(&impl->write_buffer, false);

    // version (1 byte) + command (1 byte) + reserved (1 byte) + address type (1 byte) +
    //   address length (1 byte) + address (variable length) + port (2 bytes)
    size_t requiredBytes = 7 + impl->config->proxy_host.len;
    aws_byte_buf_reserve(&impl->write_buffer, requiredBytes);

    aws_byte_buf_write_u8(&impl->write_buffer, SOCKS_VERSION);                         // version byte
    aws_byte_buf_write_u8(&impl->write_buffer, SOCKS_COMMAND_TYPE_CONNECT);            // command byte
    aws_byte_buf_write_u8(&impl->write_buffer, SOCKS_COMMAND_RESERVED_VALUE);          // reserved byte
    aws_byte_buf_write_u8(&impl->write_buffer, AWS_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);   // address type byte
    aws_byte_buf_write_u8(&impl->write_buffer, (uint8_t)impl->config->proxy_host.len); // address length byte

    struct aws_byte_cursor connect_cursor = aws_byte_cursor_from_buf(&impl->config->proxy_host);
    aws_byte_buf_append(&impl->write_buffer, &connect_cursor);              // address
    aws_byte_buf_write_be16(&impl->write_buffer, impl->config->proxy_port); // port

    impl->pending_write_data = aws_byte_cursor_from_buf(&impl->write_buffer);
}

static void s_handle_socks5_impl_state_pending_auth_subnegotiation(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {

    struct aws_socks5_negotiation_context auth_context = *context;
    aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(impl->auth_instance, &auth_context);

    context->data = auth_context.data;
    context->error_code = auth_context.error_code;

    switch (auth_context.status) {
        case AWS_S5PS_SUCCESS:
            s_build_connect_request(impl);
            s_transition_socks5_impl_state(impl, AWS_S5PIS_PENDING_REQUEST);
            break;

        case AWS_S5PS_FAILURE:
            context->status = AWS_S5PS_FAILURE;
            s_on_socks5_protocol_error(impl, context, auth_context.error_code);
            s_transition_socks5_impl_state(impl, AWS_S5PIS_FAILURE);
            break;

        default:
            break;
    }
}

static void s_handle_socks5_impl_state_pending_request(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {
    size_t write_length =
        aws_min_size(context->to_write->capacity - context->to_write->len, impl->pending_write_data.len);
    if (write_length > 0) {
        struct aws_byte_cursor to_copy = aws_byte_cursor_advance(&impl->pending_write_data, write_length);
        aws_byte_buf_append(context->to_write, &to_copy);
    }

    if (impl->pending_write_data.len == 0) {
        aws_byte_buf_reset(&impl->read_buffer, false);
        s_transition_socks5_impl_state(impl, AWS_S5PIS_PENDING_RESPONSE);
    }
}

static bool s_read_required_bytes_for_response(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context,
    size_t num_bytes_required) {

    if (impl->read_buffer.len >= num_bytes_required) {
        return true;
    }

    if (context->data != NULL) {
        size_t read_length = aws_min_size(context->data->len, num_bytes_required - impl->read_buffer.len);
        if (read_length > 0) {
            struct aws_byte_cursor to_copy = aws_byte_cursor_advance(context->data, read_length);
            aws_byte_buf_append_dynamic(&impl->read_buffer, &to_copy);
        }
    }

    return impl->read_buffer.len >= num_bytes_required;
}

static int s_calculate_response_bytes_required(struct aws_socks5_proxy_impl *impl, size_t *bytes_required) {
    if (impl->read_buffer.len < MINIMUM_RESPONSE_BYTES_REQUIRED) {
        return aws_raise_error(AWS_IO_SOCKS5_INTERNAL_FAILURE);
    }

    uint8_t address_type = impl->read_buffer.buffer[SOCKS_RESPONSE_ADDRESS_TYPE_INDEX];
    switch (address_type) {
        case AWS_SOCKS5_ADDRESS_TYPE_IPV4:
            *bytes_required = SOCKS_RESPONSE_LENGTH_IPV4;
            break;

        case AWS_SOCKS5_ADDRESS_TYPE_DOMAIN_NAME:
            *bytes_required = SOCKS_RESPONSE_LENGTH_DOMAIN_NAME_FIXED +
                              impl->read_buffer.buffer[SOCKS_RESPONSE_ADDRESS_TYPE_INDEX + 1];
            break;

        case AWS_SOCKS5_ADDRESS_TYPE_IPV6:
            *bytes_required = SOCKS_RESPONSE_LENGTH_IPV6;
            break;

        default:
            return aws_raise_error(AWS_IO_SOCKS5_PROTOCOL_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static const char *s_socks5_reply_code_strings[] = {
    "Succceeded",
    "GeneralFailure",
    "ConnectionForbidden",
    "NetworkUnreachable",
    "HostUnreachable",
    "ConnectionRefused",
    "TTLExpired",
    "CommandNotSupported",
    "AddressTypeNotSupported",
};

static void s_handle_socks5_impl_state_pending_response(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {

    if (!s_read_required_bytes_for_response(impl, context, MINIMUM_RESPONSE_BYTES_REQUIRED)) {
        return;
    }

    size_t actual_bytes_required = 0;
    if (s_calculate_response_bytes_required(impl, &actual_bytes_required)) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "(%p) Failed to parse response", (void *)impl);
        s_on_socks5_protocol_error(impl, context, aws_last_error());
        s_transition_socks5_impl_state(impl, AWS_S5PIS_FAILURE);
        return;
    }

    if (!s_read_required_bytes_for_response(impl, context, actual_bytes_required)) {
        return;
    }

    // we have the whole response, now check the reply code

    uint8_t reply_code = impl->read_buffer.buffer[SOCKS_RESPONSE_REPLY_CODE_INDEX];
    if (reply_code != 0) {
        if (reply_code < AWS_ARRAY_SIZE(s_socks5_reply_code_strings)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "(%p) Connect request rejected with reply code %d(%s)",
                (void *)impl,
                (int)reply_code,
                s_socks5_reply_code_strings[reply_code]);
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "(%p) Connect request rejected with unknown reply code %d",
                (void *)impl,
                (int)reply_code);
        }
        context->status = AWS_S5PS_FAILURE;
        s_on_socks5_protocol_error(impl, context, AWS_IO_SOCKS5_CONNECT_REQUEST_FAILED);
        s_transition_socks5_impl_state(impl, AWS_S5PIS_FAILURE);
        return;
    }

    AWS_LOGF_INFO(AWS_LS_IO_SOCKS5, "(%p) Connect request successful", (void *)impl);
    context->status = AWS_S5PS_SUCCESS;
    s_transition_socks5_impl_state(impl, AWS_S5PIS_SUCCESS);
}

void aws_socks5_proxy_impl_drive_negotiation(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {
    context->status = AWS_S5PS_IN_PROGRESS;

    enum aws_socks5_proxy_impl_state last_state = AWS_S5PIS_INVALID;
    while (last_state != impl->state) {
        last_state = impl->state;
        switch (impl->state) {
            case AWS_S5PIS_START:
                s_handle_socks5_impl_state_start(impl, context);
                break;

            case AWS_S5PIS_PENDING_METHOD_REQUEST:
                s_handle_socks5_impl_state_pending_method_request(impl, context);
                break;

            case AWS_S5PIS_PENDING_AUTH_SUBNEGOTIATION:
                s_handle_socks5_impl_state_pending_auth_subnegotiation(impl, context);
                break;

            case AWS_S5PIS_PENDING_REQUEST:
                s_handle_socks5_impl_state_pending_request(impl, context);
                break;

            case AWS_S5PIS_PENDING_RESPONSE:
                s_handle_socks5_impl_state_pending_response(impl, context);
                break;

            case AWS_S5PIS_SUCCESS:
                context->status = AWS_S5PS_SUCCESS;
                break;

            default:
                context->status = AWS_S5PS_FAILURE;
                context->error_code = impl->final_error_code;
                break;
        }
    }
}

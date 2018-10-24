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
#include <aws/io/channel_bootstrap.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>

#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/socket_channel_handler.h>
#include <aws/io/tls_channel_handler.h>

#include <assert.h>

#if _MSC_VER
/* non-constant aggregate initializer */
#    pragma warning(disable : 4204)
/* allow automatic variable to escape scope
   (it's intenional and we make sure it doesn't actually return
    before the task is finished).*/
#    pragma warning(disable : 4221)
#endif

#define MAX_HOST_RESOLVER_ENTRIES 64
#define DEFAULT_DNS_TTL 30

struct tl_shutdown_task_data {
    struct aws_condition_variable *condition_variable;
    struct aws_mutex *mutex;
    bool invoked;
};

static bool s_tl_cleanup_predicate(void *arg) {
    struct tl_shutdown_task_data *shutdown_task_data = arg;
    return shutdown_task_data->invoked;
}

static void s_handle_tl_cleanup_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct tl_shutdown_task_data *shutdown_task_data = arg;

    aws_mutex_lock(shutdown_task_data->mutex);
    aws_tls_clean_up_thread_local_state();
    shutdown_task_data->invoked = true;
    aws_condition_variable_notify_one(shutdown_task_data->condition_variable);
    aws_mutex_unlock(shutdown_task_data->mutex);
}

static void s_ensure_tl_state_is_cleaned_up(struct aws_event_loop_group *el_group) {
    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    aws_mutex_lock(&mutex);
    size_t len = aws_event_loop_group_get_loop_count(el_group);
    for (size_t i = 0; i < len; ++i) {
        struct aws_event_loop *el = aws_event_loop_group_get_loop_at(el_group, i);

        struct tl_shutdown_task_data tl_shutdown = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .invoked = false,
        };

        struct aws_task task = {
            .fn = s_handle_tl_cleanup_task,
            .arg = &tl_shutdown,
        };

        aws_event_loop_schedule_task_now(el, &task);
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tl_cleanup_predicate, &tl_shutdown);
    }
    aws_mutex_unlock(&mutex);
}

int aws_client_bootstrap_init(
    struct aws_client_bootstrap *bootstrap,
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group,
    struct aws_host_resolver *host_resolver,
    struct aws_host_resolution_config *host_resolution_config) {
    assert(allocator);
    assert(el_group);

    bootstrap->allocator = allocator;
    bootstrap->event_loop_group = el_group;
    bootstrap->tls_ctx = NULL;
    bootstrap->on_protocol_negotiated = NULL;

    if (host_resolver) {
        bootstrap->host_resolver = host_resolver;
        bootstrap->owns_resolver = false;
    } else {
        bootstrap->host_resolver = aws_mem_acquire(allocator, sizeof(struct aws_host_resolver));
        if (!bootstrap->host_resolver) {
            return AWS_OP_ERR;
        }

        if (aws_host_resolver_init_default(bootstrap->host_resolver, allocator, MAX_HOST_RESOLVER_ENTRIES)) {
            aws_mem_release(allocator, bootstrap->host_resolver);
            return AWS_OP_ERR;
        }

        bootstrap->owns_resolver = true;
    }

    if (host_resolution_config) {
        bootstrap->host_resolver_config = *host_resolution_config;
    } else {
        bootstrap->host_resolver_config = (struct aws_host_resolution_config){
            .impl = aws_default_dns_resolve,
            .max_ttl = DEFAULT_DNS_TTL,
            .impl_data = NULL,
        };
    }

    return AWS_OP_SUCCESS;
}

int aws_client_bootstrap_set_tls_ctx(struct aws_client_bootstrap *bootstrap, struct aws_tls_ctx *ctx) {
    assert(ctx);
    bootstrap->tls_ctx = ctx;
    return AWS_OP_SUCCESS;
}

int aws_client_bootstrap_set_alpn_callback(
    struct aws_client_bootstrap *bootstrap,
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated) {
    assert(on_protocol_negotiated);
    assert(bootstrap->tls_ctx);

    bootstrap->on_protocol_negotiated = on_protocol_negotiated;
    return AWS_OP_SUCCESS;
}

void aws_client_bootstrap_clean_up(struct aws_client_bootstrap *bootstrap) {
    if (bootstrap->tls_ctx) {
        s_ensure_tl_state_is_cleaned_up(bootstrap->event_loop_group);
    }

    if (bootstrap->host_resolver && bootstrap->owns_resolver) {
        aws_host_resolver_clean_up(bootstrap->host_resolver);
        aws_mem_release(bootstrap->allocator, bootstrap->host_resolver);
    }

    AWS_ZERO_STRUCT(*bootstrap);
}

struct client_channel_data {
    struct aws_channel channel;
    struct aws_socket *socket;
    struct aws_tls_connection_options tls_options;
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated;
    aws_tls_on_data_read_fn *user_on_data_read;
    aws_tls_on_negotiation_result_fn *user_on_negotiation_result;
    aws_tls_on_error_fn *user_on_error;
    void *tls_user_data;
    bool use_tls;
};

struct client_connection_args {
    struct aws_client_bootstrap *bootstrap;
    aws_client_bootstrap_on_channel_setup_fn *setup_callback;
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback;
    struct client_channel_data channel_data;
    struct aws_socket_options outgoing_options;
    uint16_t outgoing_port;
    struct aws_string *host_name;
    void *user_data;
    uint8_t addresses_count;
    uint8_t failed_count;
    bool connection_chosen;
};

static void s_tls_client_on_negotiation_result(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err_code,
    void *user_data) {
    struct client_connection_args *connection_args = user_data;

    if (connection_args->channel_data.user_on_negotiation_result) {
        connection_args->channel_data.user_on_negotiation_result(
            handler, slot, err_code, connection_args->channel_data.tls_user_data);
    }

    if (!err_code) {
        connection_args->setup_callback(
            connection_args->bootstrap,
            AWS_OP_SUCCESS,
            &connection_args->channel_data.channel,
            connection_args->user_data);
    } else {
        /* the tls handler is responsible for calling shutdown when this fails. */
        connection_args->setup_callback(connection_args->bootstrap, err_code, NULL, connection_args->user_data);
    }
}

/* in the context of a channel bootstrap, we don't care about these, but since we're hooking into these APIs we have to
 * provide a proxy for the user actually receiving their callbacks. */
static void s_tls_client_on_data_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buffer,
    void *user_data) {
    struct client_connection_args *connection_args = user_data;

    if (connection_args->channel_data.user_on_data_read) {
        connection_args->channel_data.user_on_data_read(
            handler, slot, buffer, connection_args->channel_data.tls_user_data);
    }
}

/* in the context of a channel bootstrap, we don't care about these, but since we're hooking into these APIs we have to
 * provide a proxy for the user actually receiving their callbacks. */
static void s_tls_client_on_error(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err,
    const char *message,
    void *user_data) {
    struct client_connection_args *connection_args = user_data;

    if (connection_args->channel_data.user_on_error) {
        connection_args->channel_data.user_on_error(
            handler, slot, err, message, connection_args->channel_data.tls_user_data);
    }
}

static inline int s_setup_client_tls(struct client_connection_args *connection_args, struct aws_channel *channel) {
    struct aws_channel_slot *tls_slot = aws_channel_slot_new(channel);

    /* as far as cleanup goes, since this stuff is being added to a channel, the caller will free this memory
       when they clean up the channel. */
    if (!tls_slot) {
        return AWS_OP_ERR;
    }

    struct aws_channel_handler *tls_handler = aws_tls_client_handler_new(
        connection_args->bootstrap->allocator,
        connection_args->bootstrap->tls_ctx,
        &connection_args->channel_data.tls_options,
        tls_slot);

    if (!tls_handler) {
        aws_mem_release(connection_args->bootstrap->allocator, (void *)tls_slot);
        return AWS_OP_ERR;
    }

    aws_channel_slot_insert_end(channel, tls_slot);
    if (aws_channel_slot_set_handler(tls_slot, tls_handler)) {
        return AWS_OP_ERR;
    }

    if (connection_args->channel_data.on_protocol_negotiated) {
        struct aws_channel_slot *alpn_slot = aws_channel_slot_new(channel);

        if (!alpn_slot) {
            return AWS_OP_ERR;
        }

        struct aws_channel_handler *alpn_handler = aws_tls_alpn_handler_new(
            connection_args->bootstrap->allocator,
            connection_args->channel_data.on_protocol_negotiated,
            connection_args->user_data);

        if (!alpn_handler) {
            aws_mem_release(connection_args->bootstrap->allocator, (void *)alpn_slot);
            return AWS_OP_ERR;
        }

        aws_channel_slot_insert_right(tls_slot, alpn_slot);
        if (aws_channel_slot_set_handler(alpn_slot, alpn_handler)) {
            return AWS_OP_ERR;
        }
    }

    if (aws_tls_client_handler_start_negotiation(tls_handler)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_on_client_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    struct client_connection_args *connection_args = user_data;
    int err_code = error_code;

    if (!err_code) {
        struct aws_channel_slot *socket_slot = aws_channel_slot_new(channel);

        if (!socket_slot) {
            err_code = aws_last_error();
            goto error;
        }

        struct aws_channel_handler *socket_channel_handler = aws_socket_handler_new(
            connection_args->bootstrap->allocator,
            connection_args->channel_data.socket,
            socket_slot,
            AWS_SOCKET_HANDLER_DEFAULT_MAX_READ);

        if (!socket_channel_handler) {
            err_code = aws_last_error();
            goto error;
        }

        if (aws_channel_slot_set_handler(socket_slot, socket_channel_handler)) {
            err_code = aws_last_error();
            goto error;
        }

        if (connection_args->channel_data.use_tls) {
            /* we don't want to notify the user that the channel is ready yet, since tls is still negotiating, wait
             * for the negotiation callback and handle it then.*/
            if (s_setup_client_tls(connection_args, channel)) {
                err_code = aws_last_error();
                goto error;
            }
        } else {
            connection_args->setup_callback(
                connection_args->bootstrap, AWS_OP_SUCCESS, channel, connection_args->user_data);
        }

        return;
    }

error:
    struct aws_client_bootstrap *bootstrap = connection_args->bootstrap;
    void *setup_user_data = connection_args->user_data;
    aws_client_bootstrap_on_channel_setup_fn *setup_callback = connection_args->setup_callback;
    setup_callback(bootstrap, err_code, NULL, setup_user_data);

    aws_channel_clean_up(channel);
    aws_socket_clean_up(connection_args->channel_data.socket);
    aws_mem_release(connection_args->bootstrap->allocator, connection_args->channel_data.socket);
    if (connection_args->host_name) {
        aws_string_destroy((void *)connection_args->host_name);
    }

    aws_mem_release(connection_args->bootstrap->allocator, connection_args);
}

static void s_on_client_channel_on_shutdown(struct aws_channel *channel, int error_code, void *user_data) {
    struct client_connection_args *connection_args = user_data;

    struct aws_client_bootstrap *bootstrap = connection_args->bootstrap;
    void *shutdown_user_data = connection_args->user_data;
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback = connection_args->shutdown_callback;
    shutdown_callback(bootstrap, error_code, channel, shutdown_user_data);

    aws_channel_clean_up(channel);
    aws_socket_clean_up(connection_args->channel_data.socket);
    aws_mem_release(connection_args->bootstrap->allocator, connection_args->channel_data.socket);
    if (connection_args->host_name) {
        aws_string_destroy((void *)connection_args->host_name);
    }

    aws_mem_release(connection_args->bootstrap->allocator, connection_args);
}

static void s_on_client_connection_established(struct aws_socket *socket, int error_code, void *user_data) {
    struct client_connection_args *connection_args = user_data;

    if (error_code) {
        connection_args->failed_count++;
    }

    if (error_code || connection_args->connection_chosen) {
        if (connection_args->outgoing_options.domain != AWS_SOCKET_LOCAL) {
            struct aws_host_address host_address;
            host_address.host = connection_args->host_name;
            host_address.address =
                aws_string_new_from_c_str(connection_args->bootstrap->allocator, socket->remote_endpoint.address);
            if (host_address.address) {
                aws_host_resolver_record_connection_failure(connection_args->bootstrap->host_resolver, &host_address);
                aws_string_destroy((void *)host_address.address);
            }
        }

        aws_socket_close(socket);
        aws_socket_clean_up(socket);
        aws_mem_release(connection_args->bootstrap->allocator, socket);

        if (connection_args->failed_count == connection_args->addresses_count) {
            connection_args->setup_callback(connection_args->bootstrap, error_code, NULL, connection_args->user_data);
            if (connection_args->host_name) {
                aws_string_destroy((void *)connection_args->host_name);
            }
            aws_mem_release(connection_args->bootstrap->allocator, connection_args);
        }
        return;
    }

    connection_args->connection_chosen = true;
    connection_args->channel_data.socket = socket;

    struct aws_channel_creation_callbacks channel_callbacks = {
        .on_setup_completed = s_on_client_channel_on_setup_completed,
        .setup_user_data = connection_args,
        .shutdown_user_data = connection_args,
        .on_shutdown_completed = s_on_client_channel_on_shutdown,
    };

    if (aws_channel_init(
            &connection_args->channel_data.channel,
            connection_args->bootstrap->allocator,
            aws_socket_get_event_loop(socket),
            &channel_callbacks)) {

        aws_socket_clean_up(socket);
        aws_mem_release(connection_args->bootstrap->allocator, connection_args->channel_data.socket);
        connection_args->failed_count++;

        if (connection_args->failed_count == connection_args->addresses_count) {
            connection_args->setup_callback(connection_args->bootstrap, error_code, NULL, connection_args->user_data);
            if (connection_args->host_name) {
                aws_string_destroy((void *)connection_args->host_name);
            }
            aws_mem_release(connection_args->bootstrap->allocator, connection_args);
        }
    }
}

static void s_on_host_resolved(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {
    (void)resolver;
    (void)host_name;

    struct client_connection_args *client_connection_args = user_data;

    if (!err_code) {
        size_t host_addresses_len = aws_array_list_length(host_addresses);
        /* use this event loop for all outgoing connection attempts (only one will ultimately win). */
        struct aws_event_loop *connect_loop =
            aws_event_loop_group_get_next_loop(client_connection_args->bootstrap->event_loop_group);
        client_connection_args->addresses_count = (uint8_t)host_addresses_len;

        for (size_t i = 0; i < host_addresses_len; ++i) {
            struct aws_host_address *host_address_ptr = NULL;
            aws_array_list_get_at(host_addresses, (void *)&host_address_ptr, i);

            struct aws_socket_endpoint connection_endpoint;
            connection_endpoint.port = client_connection_args->outgoing_port;

            assert(sizeof(connection_endpoint.address) >= host_address_ptr->address->len + 1);
            memcpy(
                connection_endpoint.address,
                aws_string_bytes(host_address_ptr->address),
                host_address_ptr->address->len);
            connection_endpoint.address[host_address_ptr->address->len] = 0;

            struct aws_socket_options options = client_connection_args->outgoing_options;
            options.domain =
                host_address_ptr->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ? AWS_SOCKET_IPV6 : AWS_SOCKET_IPV4;

            struct aws_socket *outgoing_socket =
                aws_mem_acquire(client_connection_args->bootstrap->allocator, sizeof(struct aws_socket));

            if (aws_socket_init(outgoing_socket, client_connection_args->bootstrap->allocator, &options)) {
                client_connection_args->failed_count++;
                aws_mem_release(client_connection_args->bootstrap->allocator, outgoing_socket);
                break;
            }

            if (aws_socket_connect(
                    outgoing_socket,
                    &connection_endpoint,
                    connect_loop,
                    s_on_client_connection_established,
                    client_connection_args)) {
                client_connection_args->failed_count++;
                aws_host_resolver_record_connection_failure(
                    client_connection_args->bootstrap->host_resolver, host_address_ptr);
                aws_socket_clean_up(outgoing_socket);
                aws_mem_release(client_connection_args->bootstrap->allocator, outgoing_socket);
                continue;
            }
        }

        if (client_connection_args->failed_count < client_connection_args->addresses_count) {
            return;
        }
    }

    client_connection_args->setup_callback(
        client_connection_args->bootstrap, aws_last_error(), NULL, client_connection_args->user_data);
    if (client_connection_args->host_name) {
        aws_string_destroy((void *)client_connection_args->host_name);
    }
    aws_mem_release(client_connection_args->bootstrap->allocator, client_connection_args);
}

static inline int s_new_client_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
    assert(setup_callback);
    assert(shutdown_callback);

    struct client_connection_args *client_connection_args =
        aws_mem_acquire(bootstrap->allocator, sizeof(struct client_connection_args));

    if (!client_connection_args) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*client_connection_args);
    client_connection_args->user_data = user_data;
    client_connection_args->bootstrap = bootstrap;
    client_connection_args->setup_callback = setup_callback;
    client_connection_args->shutdown_callback = shutdown_callback;
    client_connection_args->outgoing_options = *options;
    client_connection_args->outgoing_port = port;

    if (connection_options) {
        client_connection_args->channel_data.use_tls = true;
        client_connection_args->channel_data.tls_options = *connection_options;
        client_connection_args->channel_data.on_protocol_negotiated = bootstrap->on_protocol_negotiated;
        client_connection_args->channel_data.tls_user_data = connection_options->user_data;

        /* in order to honor any callbacks a user may have installed on their tls_connection_options,
         * we need to wrap them if they were set.*/
        if (bootstrap->on_protocol_negotiated) {
            client_connection_args->channel_data.tls_options.advertise_alpn_message = true;
        }

        if (connection_options->on_data_read) {
            client_connection_args->channel_data.user_on_data_read = connection_options->on_data_read;
            client_connection_args->channel_data.tls_options.on_data_read = s_tls_client_on_data_read;
        }

        if (connection_options->on_error) {
            client_connection_args->channel_data.user_on_error = connection_options->on_error;
            client_connection_args->channel_data.tls_options.on_error = s_tls_client_on_error;
        }

        if (connection_options->on_negotiation_result) {
            client_connection_args->channel_data.user_on_negotiation_result = connection_options->on_negotiation_result;
        }

        client_connection_args->channel_data.tls_options.on_negotiation_result = s_tls_client_on_negotiation_result;
        client_connection_args->channel_data.tls_options.user_data = client_connection_args;
    }

    if (options->domain != AWS_SOCKET_LOCAL) {
        client_connection_args->host_name = aws_string_new_from_c_str(bootstrap->allocator, host_name);

        if (!client_connection_args->host_name) {
            goto error;
        }

        if (aws_host_resolver_resolve_host(
                bootstrap->host_resolver,
                client_connection_args->host_name,
                s_on_host_resolved,
                &bootstrap->host_resolver_config,
                client_connection_args)) {
            goto error;
        }
    } else {
        struct aws_socket_endpoint endpoint;
        AWS_ZERO_STRUCT(endpoint);
        memcpy(endpoint.address, host_name, strlen(host_name));
        endpoint.port = 0;

        struct aws_socket *outgoing_socket = aws_mem_acquire(bootstrap->allocator, sizeof(struct aws_socket));

        if (!outgoing_socket) {
            goto error;
        }

        if (aws_socket_init(outgoing_socket, bootstrap->allocator, options)) {
            aws_mem_release(bootstrap->allocator, outgoing_socket);
            goto error;
        }

        client_connection_args->addresses_count = 1;

        struct aws_event_loop *connect_loop = aws_event_loop_group_get_next_loop(bootstrap->event_loop_group);

        if (aws_socket_connect(
                outgoing_socket, &endpoint, connect_loop, s_on_client_connection_established, client_connection_args)) {
            aws_socket_clean_up(outgoing_socket);
            aws_mem_release(client_connection_args->bootstrap->allocator, outgoing_socket);
            goto error;
        }
    }

    return AWS_OP_SUCCESS;

error:
    if (client_connection_args) {
        if (client_connection_args->host_name) {
            aws_string_destroy((void *)client_connection_args->host_name);
        }

        aws_mem_release(bootstrap->allocator, client_connection_args);
    }
    return AWS_OP_ERR;
}

int aws_client_bootstrap_new_tls_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
    assert(connection_options);
    assert(bootstrap->tls_ctx);

    return s_new_client_channel(
        bootstrap, host_name, port, options, connection_options, setup_callback, shutdown_callback, user_data);
}

int aws_client_bootstrap_new_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
    return s_new_client_channel(
        bootstrap, host_name, port, options, NULL, setup_callback, shutdown_callback, user_data);
}

int aws_server_bootstrap_init(
    struct aws_server_bootstrap *bootstrap,
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group) {
    assert(allocator);
    assert(el_group);

    bootstrap->allocator = allocator;
    bootstrap->event_loop_group = el_group;
    bootstrap->tls_ctx = NULL;
    bootstrap->on_protocol_negotiated = NULL;

    return AWS_OP_SUCCESS;
}

void aws_server_bootstrap_clean_up(struct aws_server_bootstrap *bootstrap) {
    if (bootstrap->tls_ctx) {
        s_ensure_tl_state_is_cleaned_up(bootstrap->event_loop_group);
    }
    AWS_ZERO_STRUCT(*bootstrap);
}

struct server_connection_args {
    struct aws_server_bootstrap *bootstrap;
    struct aws_socket listener;
    aws_server_bootstrap_on_accept_channel_setup_fn *incoming_callback;
    aws_server_bootsrap_on_accept_channel_shutdown_fn *shutdown_callback;
    struct aws_tls_connection_options tls_options;
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated;
    aws_tls_on_data_read_fn *user_on_data_read;
    aws_tls_on_negotiation_result_fn *user_on_negotiation_result;
    aws_tls_on_error_fn *user_on_error;
    void *tls_user_data;
    void *user_data;
    bool use_tls;
};

struct server_channel_data {
    struct aws_channel channel;
    struct aws_socket *socket;
    struct server_connection_args *server_connection_args;
};

static void s_tls_server_on_negotiation_result(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err_code,
    void *user_data) {
    struct server_connection_args *connection_args = user_data;

    if (connection_args->user_on_negotiation_result) {
        connection_args->user_on_negotiation_result(handler, slot, err_code, connection_args->tls_user_data);
    }

    if (!err_code) {
        connection_args->incoming_callback(
            connection_args->bootstrap, AWS_OP_SUCCESS, slot->channel, connection_args->user_data);
    } else {
        /* the tls handler is responsible for calling shutdown when this fails. */
        connection_args->shutdown_callback(connection_args->bootstrap, err_code, NULL, connection_args->user_data);
    }
}

/* in the context of a channel bootstrap, we don't care about these, but since we're hooking into these APIs we have to
 * provide a proxy for the user actually receiving their callbacks. */
static void s_tls_server_on_data_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buffer,
    void *user_data) {
    struct server_connection_args *connection_args = user_data;

    if (connection_args->user_on_data_read) {
        connection_args->user_on_data_read(handler, slot, buffer, connection_args->tls_user_data);
    }
}

/* in the context of a channel bootstrap, we don't care about these, but since we're hooking into these APIs we have to
 * provide a proxy for the user actually receiving their callbacks. */
static void s_tls_server_on_error(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err,
    const char *message,
    void *user_data) {
    struct server_connection_args *connection_args = user_data;

    if (connection_args->user_on_error) {
        connection_args->user_on_error(handler, slot, err, message, connection_args->tls_user_data);
    }
}

static inline int s_setup_server_tls(struct server_connection_args *connection_args, struct aws_channel *channel) {
    struct aws_channel_slot *tls_slot = NULL;
    struct aws_channel_handler *tls_handler = NULL;

    /* as far as cleanup goes here, since we're adding things to a channel, if a slot is ever successfully
       added to the channel, we leave it there. The caller will clean up the channel and it will clean this memory
       up as well. */
    tls_slot = aws_channel_slot_new(channel);

    if (!tls_slot) {
        return AWS_OP_ERR;
    }

    tls_handler = aws_tls_server_handler_new(
        connection_args->bootstrap->allocator,
        connection_args->bootstrap->tls_ctx,
        &connection_args->tls_options,
        tls_slot);

    if (!tls_handler) {
        aws_mem_release(connection_args->bootstrap->allocator, tls_slot);
        return AWS_OP_ERR;
    }

    aws_channel_slot_insert_end(channel, tls_slot);

    if (aws_channel_slot_set_handler(tls_slot, tls_handler)) {
        return AWS_OP_ERR;
    }

    if (connection_args->on_protocol_negotiated) {
        struct aws_channel_slot *alpn_slot = NULL;
        struct aws_channel_handler *alpn_handler = NULL;
        alpn_slot = aws_channel_slot_new(channel);

        if (!alpn_slot) {
            return AWS_OP_ERR;
        }

        alpn_handler = aws_tls_alpn_handler_new(
            connection_args->bootstrap->allocator, connection_args->on_protocol_negotiated, connection_args->user_data);

        if (!alpn_handler) {
            aws_mem_release(connection_args->bootstrap->allocator, alpn_slot);
            return AWS_OP_ERR;
        }

        aws_channel_slot_insert_right(tls_slot, alpn_slot);

        if (aws_channel_slot_set_handler(alpn_slot, alpn_handler)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_on_server_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    struct server_channel_data *channel_data = user_data;

    int err_code = error_code;
    if (!err_code) {
        struct aws_channel_slot *socket_slot = aws_channel_slot_new(channel);

        if (!socket_slot) {
            err_code = aws_last_error();
            goto error;
        }

        struct aws_channel_handler *socket_channel_handler = aws_socket_handler_new(
            channel_data->server_connection_args->bootstrap->allocator,
            channel_data->socket,
            socket_slot,
            AWS_SOCKET_HANDLER_DEFAULT_MAX_READ);

        if (!socket_channel_handler) {
            err_code = aws_last_error();
            goto error;
        }

        if (aws_channel_slot_set_handler(socket_slot, socket_channel_handler)) {
            err_code = aws_last_error();
            goto error;
        }

        if (channel_data->server_connection_args->use_tls) {
            /* incoming callback will be invoked upon the negotiation completion so don't do it
             * here. */
            if (s_setup_server_tls(channel_data->server_connection_args, channel)) {
                err_code = aws_last_error();
                goto error;
            }
        } else {
            channel_data->server_connection_args->incoming_callback(
                channel_data->server_connection_args->bootstrap,
                AWS_OP_SUCCESS,
                channel,
                channel_data->server_connection_args->user_data);
        }
        return;
    }

error:
    aws_channel_clean_up(channel);
    struct aws_allocator *allocator = channel_data->socket->allocator;
    aws_socket_clean_up(channel_data->socket);
    aws_mem_release(allocator, (void *)channel_data->socket);
    channel_data->server_connection_args->incoming_callback(
        channel_data->server_connection_args->bootstrap,
        err_code,
        NULL,
        channel_data->server_connection_args->user_data);
    aws_mem_release(channel_data->server_connection_args->bootstrap->allocator, channel_data);
}

static void s_on_server_channel_on_shutdown(struct aws_channel *channel, int error_code, void *user_data) {

    struct server_channel_data *channel_data = user_data;

    void *server_shutdown_user_data = channel_data->server_connection_args->user_data;
    struct aws_server_bootstrap *server_bootstrap = channel_data->server_connection_args->bootstrap;
    struct aws_allocator *allocator = server_bootstrap->allocator;

    channel_data->server_connection_args->shutdown_callback(
        server_bootstrap, error_code, channel, server_shutdown_user_data);
    aws_channel_clean_up(channel);
    aws_socket_clean_up(channel_data->socket);
    aws_mem_release(allocator, channel_data->socket);
    aws_mem_release(allocator, channel_data);
}

void s_on_server_connection_result(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    (void)socket;
    struct server_connection_args *connection_args = user_data;

    if (!error_code) {
        struct server_channel_data *channel_data =
            aws_mem_acquire(connection_args->bootstrap->allocator, sizeof(struct server_channel_data));

        if (!channel_data) {
            goto error_cleanup;
        }

        AWS_ZERO_STRUCT(*channel_data);
        channel_data->socket = new_socket;
        channel_data->server_connection_args = connection_args;

        struct aws_event_loop *event_loop =
            aws_event_loop_group_get_next_loop(connection_args->bootstrap->event_loop_group);

        struct aws_channel_creation_callbacks channel_callbacks = {
            .on_setup_completed = s_on_server_channel_on_setup_completed,
            .setup_user_data = channel_data,
            .shutdown_user_data = channel_data,
            .on_shutdown_completed = s_on_server_channel_on_shutdown,
        };

        if (aws_socket_assign_to_event_loop(new_socket, event_loop)) {
            aws_mem_release(connection_args->bootstrap->allocator, (void *)channel_data);
            goto error_cleanup;
        }

        if (aws_channel_init(
                &channel_data->channel, connection_args->bootstrap->allocator, event_loop, &channel_callbacks)) {
            aws_mem_release(connection_args->bootstrap->allocator, (void *)channel_data);
            goto error_cleanup;
        }
    } else {
        connection_args->incoming_callback(connection_args->bootstrap, error_code, NULL, connection_args->user_data);
        aws_server_bootstrap_destroy_socket_listener(connection_args->bootstrap, &connection_args->listener);
    }

    return;

error_cleanup:
    connection_args->incoming_callback(connection_args->bootstrap, aws_last_error(), NULL, connection_args->user_data);
    struct aws_allocator *allocator = new_socket->allocator;
    aws_socket_clean_up(new_socket);
    aws_mem_release(allocator, (void *)new_socket);
}

static inline struct aws_socket *s_server_new_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    const struct aws_socket_endpoint *local_endpoint,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_server_bootstrap_on_accept_channel_setup_fn *incoming_callback,
    aws_server_bootsrap_on_accept_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
    assert(incoming_callback);
    assert(shutdown_callback);

    struct server_connection_args *server_connection_args =
        aws_mem_acquire(bootstrap->allocator, sizeof(struct server_connection_args));

    if (!server_connection_args) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*server_connection_args);
    server_connection_args->user_data = user_data;
    server_connection_args->bootstrap = bootstrap;
    server_connection_args->shutdown_callback = shutdown_callback;
    server_connection_args->incoming_callback = incoming_callback;
    server_connection_args->on_protocol_negotiated = bootstrap->on_protocol_negotiated;

    if (connection_options) {
        server_connection_args->tls_options = *connection_options;
        server_connection_args->use_tls = true;

        server_connection_args->tls_user_data = connection_options->user_data;

        /* in order to honor any callbacks a user may have installed on their tls_connection_options,
         * we need to wrap them if they were set.*/
        if (bootstrap->on_protocol_negotiated) {
            server_connection_args->tls_options.advertise_alpn_message = true;
        }

        if (connection_options->on_data_read) {
            server_connection_args->user_on_data_read = connection_options->on_data_read;
            server_connection_args->tls_options.on_data_read = s_tls_server_on_data_read;
        }

        if (connection_options->on_error) {
            server_connection_args->user_on_error = connection_options->on_error;
            server_connection_args->tls_options.on_error = s_tls_server_on_error;
        }

        if (connection_options->on_negotiation_result) {
            server_connection_args->user_on_negotiation_result = connection_options->on_negotiation_result;
        }

        server_connection_args->tls_options.on_negotiation_result = s_tls_server_on_negotiation_result;
        server_connection_args->tls_options.user_data = server_connection_args;
    }

    struct aws_event_loop *connection_loop = aws_event_loop_group_get_next_loop(bootstrap->event_loop_group);

    if (aws_socket_init(&server_connection_args->listener, bootstrap->allocator, options)) {
        goto cleanup_server_connection_args;
    }

    if (aws_socket_bind(&server_connection_args->listener, local_endpoint)) {
        goto cleanup_listener;
    }

    if (aws_socket_listen(&server_connection_args->listener, 1024)) {
        goto cleanup_listener;
    }

    if (aws_socket_start_accept(
            &server_connection_args->listener,
            connection_loop,
            s_on_server_connection_result,
            server_connection_args)) {
        goto cleanup_listener;
    }

    return &server_connection_args->listener;

cleanup_listener:
    aws_socket_clean_up(&server_connection_args->listener);

cleanup_server_connection_args:
    aws_mem_release(bootstrap->allocator, (void *)server_connection_args);

    return NULL;
}

struct aws_socket *aws_server_bootstrap_new_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    const struct aws_socket_endpoint *local_endpoint,
    const struct aws_socket_options *options,
    aws_server_bootstrap_on_accept_channel_setup_fn *incoming_callback,
    aws_server_bootsrap_on_accept_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
    return s_server_new_socket_listener(
        bootstrap, local_endpoint, options, NULL, incoming_callback, shutdown_callback, user_data);
}

struct aws_socket *aws_server_bootstrap_new_tls_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    const struct aws_socket_endpoint *local_endpoint,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_server_bootstrap_on_accept_channel_setup_fn *incoming_callback,
    aws_server_bootsrap_on_accept_channel_shutdown_fn *shutdown_callback,
    void *user_data) {
    assert(connection_options);
    assert(bootstrap->tls_ctx);
    return s_server_new_socket_listener(
        bootstrap, local_endpoint, options, connection_options, incoming_callback, shutdown_callback, user_data);
}

int aws_server_bootstrap_destroy_socket_listener(struct aws_server_bootstrap *bootstrap, struct aws_socket *listener) {
    struct server_connection_args *server_connection_args =
        AWS_CONTAINER_OF(listener, struct server_connection_args, listener);

    aws_socket_stop_accept(listener);
    aws_socket_clean_up(listener);
    aws_mem_release(bootstrap->allocator, server_connection_args);
    return AWS_OP_SUCCESS;
}

int aws_server_bootstrap_set_tls_ctx(struct aws_server_bootstrap *bootstrap, struct aws_tls_ctx *ctx) {
    assert(ctx);
    bootstrap->tls_ctx = ctx;
    return AWS_OP_SUCCESS;
}

int aws_server_bootstrap_set_alpn_callback(
    struct aws_server_bootstrap *bootstrap,
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated) {
    assert(on_protocol_negotiated);
    assert(bootstrap->tls_ctx);

    bootstrap->on_protocol_negotiated = on_protocol_negotiated;
    return AWS_OP_SUCCESS;
}

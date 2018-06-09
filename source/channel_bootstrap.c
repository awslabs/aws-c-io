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
#include <aws/io/event_loop.h>
#include <aws/io/socket_channel_handler.h>
#include <assert.h>


int aws_client_bootstrap_init (struct aws_client_bootstrap *bootstrap, struct aws_allocator *allocator, struct aws_event_loop_group *el_group) {
    assert(allocator);
    assert(el_group);

    bootstrap->allocator = allocator;
    bootstrap->event_loop_group = el_group;

    return AWS_OP_SUCCESS;
}

void aws_client_bootstrap_clean_up (struct aws_client_bootstrap *bootstrap) {
    (void *)bootstrap;
}

struct client_channel_data {
    struct aws_channel channel;
    struct aws_socket socket;
};

struct client_connection_args {
    struct aws_client_bootstrap *bootstrap;
    aws_channel_client_setup_callback setup_callback;
    aws_channel_client_shutdown_callback shutdown_callback;
    struct client_channel_data channel_data;
    struct aws_event_loop *loop;
    void *user_data;
};

static void on_client_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    struct client_connection_args *connection_args = (struct client_connection_args *)user_data;

    int err_code = AWS_OP_SUCCESS;
    struct aws_channel_slot *socket_slot = aws_channel_slot_new(channel);

    if (!socket_slot) {
        err_code = aws_last_error();
        goto error;
    }

    struct aws_channel_handler *socket_channel_handler = aws_socket_handler_new(connection_args->bootstrap->allocator,
                                                            &connection_args->channel_data.socket,
                                                            socket_slot, connection_args->loop, AWS_SOCKET_HANDLER_DEFAULT_MAX_RW);

    if (!socket_channel_handler) {
        err_code = aws_last_error();
        goto error;
    }

    aws_channel_slot_set_handler(socket_slot, socket_channel_handler);
    connection_args->setup_callback(connection_args->bootstrap, AWS_OP_SUCCESS, channel, connection_args->user_data);

error:
    aws_channel_clean_up(channel);
    connection_args->setup_callback(connection_args->bootstrap, err_code, NULL, connection_args->user_data);
    aws_mem_release(connection_args->bootstrap->allocator, connection_args);
}

static void on_client_channel_on_shutdown(struct aws_channel *channel, void *user_data) {
    struct client_connection_args *connection_args = (struct client_connection_args *)user_data;

    connection_args->shutdown_callback(connection_args->bootstrap, AWS_OP_SUCCESS, channel, connection_args->user_data);
    aws_channel_clean_up(channel);
    aws_mem_release(connection_args->bootstrap->allocator, (void *)connection_args);
}

static void on_client_connection_established(struct aws_socket *socket, void *user_data) {
    struct client_connection_args *connection_args = (struct client_connection_args *)user_data;

    int err_code = AWS_OP_SUCCESS;


    struct aws_event_loop *event_loop = aws_event_loop_get_next_loop(connection_args->bootstrap->event_loop_group);
    connection_args->loop = event_loop;
    struct aws_channel_creation_callbacks channel_callbacks = {
            .on_setup_completed = on_client_channel_on_setup_completed,
            .setup_user_data = connection_args,
            .shutdown_user_data = connection_args,
            .on_shutdown_completed = on_client_channel_on_shutdown,
    };

    if (aws_channel_init(&connection_args->channel_data.channel, connection_args->bootstrap->allocator, event_loop, &channel_callbacks)) {
        err_code = aws_last_error();
        goto error;
    }

error:
    aws_socket_clean_up(socket);
    connection_args->setup_callback(connection_args->bootstrap, err_code, NULL, connection_args->user_data);
    aws_mem_release(connection_args->bootstrap->allocator, (void *)connection_args);
}

static void on_client_connection_error(struct aws_socket *socket, int err_code, void *user_data) {
    struct client_connection_args *connection_args = (struct client_connection_args *)user_data;

    connection_args->setup_callback(connection_args->bootstrap, err_code, NULL, connection_args->user_data);
    aws_socket_clean_up(&connection_args->channel_data.socket);
    aws_mem_release(connection_args->bootstrap->allocator, (void *)connection_args);
}


int aws_client_bootstrap_new_socket_channel (struct aws_client_bootstrap *bootstrap,
                                             struct aws_socket_endpoint *endpoint,
                                             struct aws_socket_options *options,
                                             aws_channel_client_setup_callback setup_callback,
                                             aws_channel_client_shutdown_callback shutdown_callback,
                                             void *user_data) {

    assert(setup_callback);
    assert(shutdown_callback);

    struct client_connection_args *client_connection_args =
            (struct client_connection_args *)aws_mem_acquire(bootstrap->allocator, sizeof(struct client_connection_args));

    if (!client_connection_args) {
        aws_mem_release(bootstrap->allocator, (void *)socket);
        return aws_raise_error(AWS_ERROR_OOM);
    }

    client_connection_args->user_data = user_data;
    client_connection_args->bootstrap = bootstrap;
    client_connection_args->setup_callback = setup_callback;
    client_connection_args->shutdown_callback = shutdown_callback;

    struct aws_event_loop *connection_loop = aws_event_loop_get_next_loop(bootstrap->event_loop_group);

    struct aws_socket_creation_args args = {
        .user_data = client_connection_args,
        .on_error = on_client_connection_error,
        .on_connection_established = on_client_connection_established,
    };

    if (aws_socket_init(&client_connection_args->channel_data.socket, bootstrap->allocator, options, connection_loop, &args)) {
        aws_mem_release(bootstrap->allocator, (void *)client_connection_args);
        return AWS_OP_ERR;
    }

    if (aws_socket_connect(&client_connection_args->channel_data.socket, endpoint)) {
        aws_socket_clean_up(&client_connection_args->channel_data.socket);
        aws_mem_release(bootstrap->allocator, (void *)client_connection_args);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_server_bootstrap_init (struct aws_server_bootstrap *bootstrap, struct aws_allocator *allocator, struct aws_event_loop_group *el_group) {
    assert(allocator);
    assert(el_group);

    bootstrap->allocator = allocator;
    bootstrap->event_loop_group = el_group;

    return AWS_OP_SUCCESS;
}

void aws_server_bootstrap_clean_up (struct aws_server_bootstrap *bootstrap) {
    (void *)bootstrap;
}

struct server_connection_args {
    struct aws_server_bootstrap *bootstrap;
    struct aws_socket listener;
    aws_channel_server_incoming_channel_callback incoming_callback;
    aws_channel_server_channel_shutdown_callback shutdown_callback;
    struct aws_event_loop *listener_loop;
    void *user_data;
};

struct server_channel_data {
    struct aws_channel channel;
    struct aws_socket *socket;
    struct server_connection_args *server_connection_args;
};



static void on_server_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    struct server_channel_data *channel_data = (struct server_channel_data *)user_data;

    int err_code = AWS_OP_SUCCESS;
    struct aws_channel_slot *socket_slot = aws_channel_slot_new(channel);

    if (!socket_slot) {
        err_code = aws_last_error();
        goto error;
    }

    struct aws_channel_handler *socket_channel_handler = aws_socket_handler_new(channel_data->server_connection_args->bootstrap->allocator,
                                                                                channel_data->socket,
                                                                                socket_slot, channel->loop, AWS_SOCKET_HANDLER_DEFAULT_MAX_RW);

    if (!socket_channel_handler) {
        err_code = aws_last_error();
        goto error;
    }

    aws_channel_slot_set_handler(socket_slot, socket_channel_handler);
    channel_data->server_connection_args->incoming_callback(channel_data->server_connection_args->bootstrap,
                                                            AWS_OP_SUCCESS, channel, channel_data->server_connection_args->user_data);
    return;

error:
    aws_channel_clean_up(channel);
    channel_data->server_connection_args->incoming_callback(channel_data->server_connection_args->bootstrap,
                                                            err_code, NULL, channel_data->server_connection_args->user_data);
    aws_socket_clean_up(channel_data->socket);
    aws_mem_release(channel_data->socket->allocator, (void *)channel_data->socket);
    aws_mem_release(channel_data->server_connection_args->bootstrap->allocator, channel_data);
}

static void on_server_channel_on_shutdown(struct aws_channel *channel, void *user_data) {
    struct server_channel_data *channel_data = (struct server_channel_data *)user_data;

    channel_data->server_connection_args->shutdown_callback(channel_data->server_connection_args->bootstrap,
                                                            AWS_OP_SUCCESS, channel, channel_data->server_connection_args->user_data);
    aws_channel_clean_up(channel);
    aws_socket_clean_up(channel_data->socket);
    aws_mem_release(channel_data->socket->allocator, (void *)channel_data->socket);
    aws_mem_release(channel_data->server_connection_args->bootstrap->allocator, channel_data);
}

void on_server_connection_established(struct aws_socket *socket, struct aws_socket *new_socket, void *user_data) {
    struct server_connection_args *connection_args = (struct server_connection_args *)user_data;

    struct server_channel_data *channel_data =
            (struct server_channel_data *)aws_mem_acquire(connection_args->bootstrap->allocator, sizeof(struct server_channel_data));

    if (!channel_data) {
        aws_raise_error(AWS_ERROR_OOM);
        connection_args->incoming_callback(connection_args->bootstrap, AWS_ERROR_OOM, NULL, connection_args->user_data);
        aws_socket_clean_up(new_socket);
        aws_mem_release(new_socket->allocator, (void *)new_socket);
        aws_mem_release(connection_args->bootstrap->allocator, connection_args);
        return;
    }

    channel_data->socket = new_socket;
    channel_data->server_connection_args = connection_args;

    struct aws_event_loop *event_loop = aws_event_loop_get_next_loop(connection_args->bootstrap->event_loop_group);

    struct aws_channel_creation_callbacks channel_callbacks = {
            .on_setup_completed = on_server_channel_on_setup_completed,
            .setup_user_data = connection_args,
            .shutdown_user_data = connection_args,
            .on_shutdown_completed = on_server_channel_on_shutdown,
    };

    if (aws_channel_init(&channel_data->channel, connection_args->bootstrap->allocator, event_loop, &channel_callbacks)) {
        connection_args->incoming_callback(connection_args->bootstrap, aws_last_error(), NULL, connection_args->user_data);
        aws_socket_clean_up(new_socket);
        aws_mem_release(new_socket->allocator, (void *)new_socket);
        aws_mem_release(connection_args->bootstrap->allocator, connection_args);
    }
}

void on_server_connection_error(struct aws_socket *socket, int err_code, void *user_data) {
    struct server_connection_args *connection_args = (struct server_connection_args *)user_data;

    connection_args->incoming_callback(connection_args->bootstrap, err_code, NULL, connection_args->user_data);
    aws_server_bootstrap_remove_socket_listener(connection_args->bootstrap, &connection_args->listener);
}


struct aws_socket *aws_server_bootstrap_add_socket_listener (struct aws_server_bootstrap *bootstrap,
                                                         struct aws_socket_endpoint *endpoint,
                                                         struct aws_socket_options *options,
                                                         aws_channel_server_incoming_channel_callback incoming_callback,
                                                         aws_channel_server_channel_shutdown_callback shutdown_callback,
                                                         void *user_data) {
    assert(incoming_callback);
    assert(shutdown_callback);

    struct server_connection_args *server_connection_args =
            (struct server_connection_args *)aws_mem_acquire(bootstrap->allocator, sizeof(struct server_connection_args));

    if (!server_connection_args) {
        aws_mem_release(bootstrap->allocator, (void *)server_connection_args);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    server_connection_args->user_data = user_data;
    server_connection_args->bootstrap = bootstrap;
    server_connection_args->shutdown_callback = shutdown_callback;
    server_connection_args->incoming_callback = incoming_callback;

    struct aws_event_loop *connection_loop = aws_event_loop_get_next_loop(bootstrap->event_loop_group);

    server_connection_args->listener_loop = connection_loop;

    struct aws_socket_creation_args args = {
            .user_data = server_connection_args,
            .on_error = on_server_connection_error,
            .on_incoming_connection = on_server_connection_established,
    };

    if (aws_socket_init(&server_connection_args->listener, bootstrap->allocator, options, connection_loop, &args)) {
        aws_mem_release(bootstrap->allocator, (void *)server_connection_args);
        return NULL;
    }

    if (aws_socket_bind(&server_connection_args->listener, endpoint)) {
        aws_socket_clean_up(&server_connection_args->listener);
        aws_mem_release(bootstrap->allocator, (void *)server_connection_args);
        return NULL;
    }

    if (aws_socket_listen(&server_connection_args->listener, 1024)) {
        aws_socket_clean_up(&server_connection_args->listener);
        aws_mem_release(bootstrap->allocator, (void *)server_connection_args);
        return NULL;
    }

    if (aws_socket_start_accept(&server_connection_args->listener)) {
        aws_socket_clean_up(&server_connection_args->listener);
        aws_mem_release(bootstrap->allocator, (void *)server_connection_args);
        return NULL;
    }

    return &server_connection_args->listener;
}

int aws_server_bootstrap_remove_socket_listener (struct aws_server_bootstrap *bootstrap,
                                                            struct aws_socket *listener) {
    struct server_connection_args *server_connection_args = (struct server_connection_args *)((uint8_t *)listener -
                                                            offsetof(struct server_connection_args, listener));

    aws_socket_stop_accept(listener);
    aws_socket_clean_up(listener);
    aws_mem_release(bootstrap->allocator, server_connection_args);
    return AWS_OP_SUCCESS;
}

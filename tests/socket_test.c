/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/private/event_loop_impl.h>
#include <aws/io/socket.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* strncpy */
#endif

#if USE_VSOCK
#    include <linux/vm_sockets.h>
#endif

struct local_listener_args {
    struct aws_socket *incoming;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    bool incoming_invoked;
    bool error_invoked;
    bool shutdown_complete;
};

static void s_local_listener_shutdown_complete(void *user_data) {
    struct local_listener_args *listener_args = (struct local_listener_args *)user_data;

    aws_mutex_lock(listener_args->mutex);
    listener_args->shutdown_complete = true;
    aws_mutex_unlock(listener_args->mutex);
    aws_condition_variable_notify_one(listener_args->condition_variable);
}

static bool s_local_listener_shutdown_completed_predicate(void *arg) {
    struct local_listener_args *listener_args = arg;

    return listener_args->shutdown_complete;
}

static bool s_incoming_predicate(void *arg) {
    struct local_listener_args *listener_args = (struct local_listener_args *)arg;

    return listener_args->incoming_invoked || listener_args->error_invoked;
}

static void s_local_listener_incoming(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    (void)socket;
    struct local_listener_args *listener_args = (struct local_listener_args *)user_data;
    aws_mutex_lock(listener_args->mutex);

    if (!error_code) {
        listener_args->incoming = new_socket;
        listener_args->incoming_invoked = true;
    } else {
        listener_args->error_invoked = true;
    }
    aws_mutex_unlock(listener_args->mutex);
    aws_condition_variable_notify_one(listener_args->condition_variable);
}

struct local_outgoing_args {
    bool connect_invoked;
    bool error_invoked;
    int last_error;
    bool shutdown_complete;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
};

static bool s_connection_completed_predicate(void *arg) {
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)arg;

    return outgoing_args->connect_invoked || outgoing_args->error_invoked;
}

static void s_local_outgoing_connection(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)user_data;

    aws_mutex_lock(outgoing_args->mutex);

    if (!error_code) {
        outgoing_args->connect_invoked = true;

    } else {
        outgoing_args->last_error = error_code;
        outgoing_args->error_invoked = true;
    }

    aws_mutex_unlock(outgoing_args->mutex);
    aws_condition_variable_notify_one(outgoing_args->condition_variable);
}

static void s_local_outgoing_connection_shutdown_complete(void *user_data) {
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)user_data;

    aws_mutex_lock(outgoing_args->mutex);
    outgoing_args->shutdown_complete = true;
    aws_mutex_unlock(outgoing_args->mutex);
    aws_condition_variable_notify_one(outgoing_args->condition_variable);
}

static bool s_outgoing_shutdown_completed_predicate(void *arg) {
    struct local_outgoing_args *io_args = arg;

    return io_args->shutdown_complete;
}

struct socket_io_args {
    struct aws_socket *socket;
    struct aws_byte_cursor *to_write;
    struct aws_byte_buf *to_read;
    struct aws_byte_buf *read_data;
    size_t amount_written;
    size_t amount_read;
    int error_code;
    bool close_completed;
    bool shutdown_complete;
    struct aws_mutex *mutex;
    struct aws_condition_variable condition_variable;
};

static bool s_shutdown_completed_predicate(void *arg) {
    struct socket_io_args *io_args = arg;

    return io_args->shutdown_complete;
}

static void s_on_written(struct aws_socket *socket, int error_code, size_t amount_written, void *user_data) {
    (void)socket;
    struct socket_io_args *write_args = user_data;
    aws_mutex_lock(write_args->mutex);
    write_args->error_code = error_code;
    write_args->amount_written = amount_written;
    aws_condition_variable_notify_one(&write_args->condition_variable);
    aws_mutex_unlock(write_args->mutex);
}

static bool s_write_completed_predicate(void *arg) {
    struct socket_io_args *io_args = arg;

    return io_args->amount_written;
}

static void s_write_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct socket_io_args *io_args = args;
    aws_socket_write(io_args->socket, io_args->to_write, s_on_written, io_args);
}

static void s_read_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct socket_io_args *io_args = args;

    aws_mutex_lock(io_args->mutex);

    size_t read = 0;

    while (read < io_args->to_read->len) {
        size_t data_len = 0;

        if (aws_socket_read(io_args->socket, io_args->read_data, &data_len)) {
            if (AWS_IO_READ_WOULD_BLOCK == aws_last_error()) {
                /* we can't just loop here, since the socket may rely on the event-loop for actually getting
                 * the data, so schedule a task to force a context switch and give the socket a chance to catch up. */
                aws_mutex_unlock(io_args->mutex);
                aws_event_loop_schedule_task_now(io_args->socket->event_loop, task);
                return;
            }
            break;
        }

        read += data_len;
    }
    io_args->amount_read = read;

    aws_mutex_unlock(io_args->mutex);
    aws_condition_variable_notify_one(&io_args->condition_variable);
}

static bool s_read_task_predicate(void *arg) {
    struct socket_io_args *io_args = arg;

    return io_args->amount_read;
}

static void s_on_readable(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)user_data;
    (void)error_code;
}

static bool s_close_completed_predicate(void *arg) {
    struct socket_io_args *io_args = (struct socket_io_args *)arg;

    return io_args->close_completed;
}

static void s_socket_close_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct socket_io_args *io_args = args;
    aws_mutex_lock(io_args->mutex);
    aws_socket_close(io_args->socket);
    io_args->close_completed = true;
    aws_mutex_unlock(io_args->mutex);
    aws_condition_variable_notify_one(&io_args->condition_variable);
}

static void s_socket_shutdown_complete_fn(void *user_data) {
    struct socket_io_args *close_args = user_data;
    aws_mutex_lock(close_args->mutex);
    close_args->shutdown_complete = true;
    aws_mutex_unlock(close_args->mutex);
    aws_condition_variable_notify_one(&close_args->condition_variable);
}
struct error_test_args {
    int error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool shutdown_invoked;
};

static bool s_socket_error_shutdown_predicate(void *args) {
    struct error_test_args *test_args = (struct error_test_args *)args;

    return test_args->shutdown_invoked;
}

static void s_socket_error_shutdown_complete(void *user_data) {
    struct error_test_args *test_args = (struct error_test_args *)user_data;

    aws_mutex_lock(&test_args->mutex);
    test_args->shutdown_invoked = true;
    aws_mutex_unlock(&test_args->mutex);
    aws_condition_variable_notify_one(&test_args->condition_variable);
}

/* we have tests that need to check the error handling path, but it's damn near
   impossible to predictably make sockets fail, the best idea we have is to
   do something the OS won't allow for the access permissions (like attempt to listen
   on a port < 1024), but alas, what if you're running the build as root? This disables
   those tests if the user runs the build as a root user. */
static bool s_test_running_as_root(struct aws_allocator *alloc) {
    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 80};
    struct aws_socket socket;

    struct aws_socket_options options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .keep_alive_interval_sec = 0,
        .keep_alive_timeout_sec = 0,
        .connect_timeout_ms = 0,
        .keepalive = 0,
    };

    int err = aws_socket_init(&socket, alloc, &options);
    AWS_FATAL_ASSERT(!err);

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};

    err = aws_socket_bind(&socket, &socket_bind_options);
    err |= aws_socket_listen(&socket, 1024);

    struct error_test_args args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_invoked = false,
    };

    aws_socket_set_cleanup_complete_callback(&socket, s_socket_error_shutdown_complete, &args);

    bool is_root = !err;
    aws_socket_clean_up(&socket);
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &args.condition_variable, &args.mutex, s_socket_error_shutdown_predicate, &args));
    ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));

    return is_root;
}

static int s_test_socket_ex(
    struct aws_allocator *allocator,
    struct aws_socket_options *options,
    struct aws_socket_endpoint *local,
    struct aws_socket_endpoint *endpoint) {

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .incoming = NULL,
        .incoming_invoked = false,
        .error_invoked = false,
    };

    /* now test the read and write across the connection. */
    const char read_data[] = "I'm a little teapot";
    char write_data[sizeof(read_data)] = {0};

    struct aws_byte_buf read_buffer = aws_byte_buf_from_array((const uint8_t *)read_data, sizeof(read_data));
    struct aws_byte_buf write_buffer = aws_byte_buf_from_array((const uint8_t *)write_data, sizeof(write_data));
    write_buffer.len = 0;

    struct aws_byte_cursor read_cursor = aws_byte_cursor_from_buf(&read_buffer);

    struct socket_io_args io_args = {
        .socket = NULL,
        .to_write = &read_cursor,
        .to_read = &read_buffer,
        .read_data = &write_buffer,
        .mutex = &mutex,
        .amount_read = 0,
        .amount_written = 0,
        .error_code = 0,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .close_completed = false,
        .shutdown_complete = false,
    };

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = endpoint};

    ASSERT_SUCCESS(aws_socket_bind(&listener, &socket_bind_options));

    struct aws_socket_endpoint bound_endpoint;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&listener, &bound_endpoint));
    ASSERT_INT_EQUALS(endpoint->port, bound_endpoint.port);
    ASSERT_STR_EQUALS(endpoint->address, bound_endpoint.address);

    // The Apple Network Framework always require a "start listener/start connection"
    // for setup a server socket
    if (options->type == AWS_SOCKET_STREAM ||
        aws_socket_get_default_impl_type() == AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {
        ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
        struct aws_socket_listener_options listener_options = {
            .on_accept_result = s_local_listener_incoming, .on_accept_result_user_data = &listener_args};
        ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));
    }

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;

    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, options));
    if (local && (strcmp(local->address, endpoint->address) != 0 || local->port != endpoint->port)) {
        struct aws_socket_bind_options socket_bind_options_local = {.local_endpoint = local};
        ASSERT_SUCCESS(aws_socket_bind(&outgoing, &socket_bind_options_local));
    }

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    if (listener.options.type == AWS_SOCKET_STREAM ||
        aws_socket_get_default_impl_type() == AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        ASSERT_SUCCESS(
            aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    }
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    struct aws_socket *server_sock = &listener;

    if (options->type == AWS_SOCKET_STREAM ||
        aws_socket_get_default_impl_type() == AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {
        ASSERT_TRUE(listener_args.incoming_invoked);
        ASSERT_FALSE(listener_args.error_invoked);
        server_sock = listener_args.incoming;
        ASSERT_TRUE(outgoing_args.connect_invoked);
        ASSERT_FALSE(outgoing_args.error_invoked);
        ASSERT_INT_EQUALS(options->domain, listener_args.incoming->options.domain);
        ASSERT_INT_EQUALS(options->type, listener_args.incoming->options.type);
    }

    ASSERT_SUCCESS(aws_socket_assign_to_event_loop(server_sock, event_loop));
    ASSERT_SUCCESS(aws_socket_subscribe_to_readable_events(server_sock, s_on_readable, NULL));
    ASSERT_SUCCESS(aws_socket_subscribe_to_readable_events(&outgoing, s_on_readable, NULL));

    io_args.socket = &outgoing;

    struct aws_task write_task = {
        .fn = s_write_task,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &write_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    io_args.socket = server_sock;
    struct aws_task read_task = {
        .fn = s_read_task,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &read_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_read_task_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);
    ASSERT_BIN_ARRAYS_EQUALS(read_buffer.buffer, read_buffer.len, write_buffer.buffer, write_buffer.len);

    if (options->type != AWS_SOCKET_DGRAM) {
        memset((void *)write_data, 0, sizeof(write_data));
        write_buffer.len = 0;

        io_args.error_code = 0;
        io_args.amount_read = 0;
        io_args.amount_written = 0;
        io_args.socket = server_sock;
        aws_event_loop_schedule_task_now(event_loop, &write_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

        io_args.socket = &outgoing;
        aws_event_loop_schedule_task_now(event_loop, &read_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_read_task_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);
        ASSERT_BIN_ARRAYS_EQUALS(read_buffer.buffer, read_buffer.len, write_buffer.buffer, write_buffer.len);
    }

    struct aws_task close_task = {
        .fn = s_socket_close_task,
        .arg = &io_args,
    };

    if (listener_args.incoming) {
        io_args.socket = listener_args.incoming;
        io_args.close_completed = false;
        io_args.shutdown_complete = false;
        aws_socket_set_cleanup_complete_callback(listener_args.incoming, s_socket_shutdown_complete_fn, &io_args);
        aws_event_loop_schedule_task_now(event_loop, &close_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

        aws_socket_clean_up(listener_args.incoming);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    io_args.shutdown_complete = false;
    aws_socket_set_cleanup_complete_callback(&outgoing, s_socket_shutdown_complete_fn, &io_args);
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&outgoing);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    io_args.socket = &listener;
    io_args.close_completed = false;
    io_args.shutdown_complete = false;
    aws_socket_set_cleanup_complete_callback(&listener, s_socket_shutdown_complete_fn, &io_args);
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&listener);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}

static int s_test_socket_udp_apple_network_framework(
    struct aws_allocator *allocator,
    struct aws_socket_options *options,
    struct aws_socket_endpoint *endpoint) {

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .incoming = NULL,
        .incoming_invoked = false,
        .error_invoked = false,
    };

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &socket_bind_options));

    struct aws_socket_endpoint bound_endpoint;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&listener, &bound_endpoint));
    ASSERT_INT_EQUALS(endpoint->port, bound_endpoint.port);
    ASSERT_STR_EQUALS(endpoint->address, bound_endpoint.address);

    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_local_listener_incoming, .on_accept_result_user_data = &listener_args};
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    ASSERT_SUCCESS(aws_socket_subscribe_to_readable_events(&outgoing, s_on_readable, NULL));

    /* now test the read and write across the connection. */
    const char read_data[] = "I'm a little teapot";
    char write_data[sizeof(read_data)] = {0};

    struct aws_byte_buf read_buffer = aws_byte_buf_from_array((const uint8_t *)read_data, sizeof(read_data));
    struct aws_byte_buf write_buffer = aws_byte_buf_from_array((const uint8_t *)write_data, sizeof(write_data));
    write_buffer.len = 0;

    struct aws_byte_cursor read_cursor = aws_byte_cursor_from_buf(&read_buffer);

    struct socket_io_args io_args = {
        .socket = &outgoing,
        .to_write = &read_cursor,
        .to_read = &read_buffer,
        .read_data = &write_buffer,
        .mutex = &mutex,
        .amount_read = 0,
        .amount_written = 0,
        .error_code = 0,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .close_completed = false,
    };

    struct aws_task write_task = {
        .fn = s_write_task,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &write_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    ASSERT_TRUE(listener_args.incoming_invoked);
    ASSERT_FALSE(listener_args.error_invoked);
    struct aws_socket *server_sock = listener_args.incoming;
    ASSERT_TRUE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(options->domain, listener_args.incoming->options.domain);
    ASSERT_INT_EQUALS(options->type, listener_args.incoming->options.type);
    ASSERT_SUCCESS(aws_socket_assign_to_event_loop(server_sock, event_loop));

    aws_socket_subscribe_to_readable_events(server_sock, s_on_readable, NULL);

    io_args.socket = server_sock;
    struct aws_task read_task = {
        .fn = s_read_task,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &read_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_read_task_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);
    ASSERT_BIN_ARRAYS_EQUALS(read_buffer.buffer, read_buffer.len, write_buffer.buffer, write_buffer.len);

    struct aws_task close_task = {
        .fn = s_socket_close_task,
        .arg = &io_args,
    };

    if (listener_args.incoming) {
        io_args.socket = listener_args.incoming;
        io_args.close_completed = false;
        io_args.shutdown_complete = false;
        aws_socket_set_cleanup_complete_callback(listener_args.incoming, s_socket_shutdown_complete_fn, &io_args);
        aws_event_loop_schedule_task_now(event_loop, &close_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

        aws_socket_clean_up(listener_args.incoming);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    io_args.shutdown_complete = false;
    aws_socket_set_cleanup_complete_callback(&outgoing, s_socket_shutdown_complete_fn, &io_args);
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&outgoing);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    io_args.socket = &listener;
    io_args.close_completed = false;
    io_args.shutdown_complete = false;
    aws_socket_set_cleanup_complete_callback(&listener, s_socket_shutdown_complete_fn, &io_args);
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&listener);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}

static int s_test_socket_creation(struct aws_allocator *alloc, enum aws_socket_impl_type type, int expected_result) {
    struct aws_socket socket;

    struct aws_socket_options options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .keep_alive_interval_sec = 0,
        .keep_alive_timeout_sec = 0,
        .connect_timeout_ms = 0,
        .keepalive = 0,
        .impl_type = type,
    };

    int err = aws_socket_init(&socket, alloc, &options);
    if (err == AWS_OP_SUCCESS) {
        aws_socket_clean_up(&socket);
        ASSERT_INT_EQUALS(err, expected_result);
    } else { // socket init failed, validate the last error
        ASSERT_INT_EQUALS(aws_last_error(), expected_result);
    }
    return AWS_OP_SUCCESS;
}

static int s_socket_test_posix_expected_result = AWS_ERROR_PLATFORM_NOT_SUPPORTED;
static int s_socket_test_winsock_expected_result = AWS_ERROR_PLATFORM_NOT_SUPPORTED;

static int s_test_socket_posix_creation(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

#if defined(AWS_ENABLE_KQUEUE) || defined(AWS_ENABLE_EPOLL)
    s_socket_test_posix_expected_result = AWS_OP_SUCCESS;
#endif
    return s_test_socket_creation(allocator, AWS_SOCKET_IMPL_POSIX, s_socket_test_posix_expected_result);
}

AWS_TEST_CASE(socket_posix_creation, s_test_socket_posix_creation)

static int s_test_socket_winsock_creation(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

#ifdef AWS_ENABLE_IO_COMPLETION_PORTS
    s_socket_test_winsock_expected_result = AWS_OP_SUCCESS;
#endif
    return s_test_socket_creation(allocator, AWS_SOCKET_IMPL_WINSOCK, s_socket_test_winsock_expected_result);
}

AWS_TEST_CASE(socket_winsock_creation, s_test_socket_winsock_creation)

static int s_test_socket(
    struct aws_allocator *allocator,
    struct aws_socket_options *options,
    struct aws_socket_endpoint *endpoint) {

    if (aws_socket_get_default_impl_type() == AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK &&
        options->type == AWS_SOCKET_DGRAM)
        return s_test_socket_udp_apple_network_framework(allocator, options, endpoint);
    else
        return s_test_socket_ex(allocator, options, NULL, endpoint);
}

static int s_test_local_socket_communication(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));
    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);
    aws_socket_endpoint_init_local_address_for_test(&endpoint);

    return s_test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(local_socket_communication, s_test_local_socket_communication)

static int s_test_tcp_socket_communication(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8127};

    return s_test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(tcp_socket_communication, s_test_tcp_socket_communication)

static int s_test_socket_with_bind_to_interface(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;
#if defined(AWS_OS_APPLE)
    strncpy(options.network_interface_name, "lo0", AWS_NETWORK_INTERFACE_NAME_MAX);
#else
    strncpy(options.network_interface_name, "lo", AWS_NETWORK_INTERFACE_NAME_MAX);
#endif
    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8128};
    if (s_test_socket(allocator, &options, &endpoint)) {
#if !defined(AWS_OS_LINUX)
        // On Apple, nw_socket currently not support network_interface_name
        if (aws_last_error() == AWS_ERROR_PLATFORM_NOT_SUPPORTED) {
            return AWS_OP_SKIP;
        }
#endif
        ASSERT_TRUE(false, "s_test_socket() failed");
    }
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;
    ASSERT_SUCCESS(s_test_socket(allocator, &options, &endpoint));

    struct aws_socket_endpoint endpoint_ipv6 = {.address = "::1", .port = 8129};
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV6;
    if (s_test_socket(allocator, &options, &endpoint_ipv6)) {
        /* Skip test if server can't bind to address (e.g. Codebuild's ubuntu runners don't allow IPv6) */
        if (aws_last_error() == AWS_IO_SOCKET_INVALID_ADDRESS) {
            return AWS_OP_SKIP;
        }
        ASSERT_TRUE(false, "s_test_socket() failed");
    }

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_socket_with_bind_to_interface, s_test_socket_with_bind_to_interface)

static int s_test_socket_with_bind_to_invalid_interface(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;
    strncpy(options.network_interface_name, "invalid", AWS_NETWORK_INTERFACE_NAME_MAX);
    struct aws_socket outgoing;
#if (defined(AWS_OS_APPLE) && !defined(AWS_USE_APPLE_NETWORK_FRAMEWORK)) || defined(AWS_OS_LINUX)
    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_OPTIONS, aws_socket_init(&outgoing, allocator, &options));
#else
    ASSERT_ERROR(AWS_ERROR_PLATFORM_NOT_SUPPORTED, aws_socket_init(&outgoing, allocator, &options));
#endif
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_socket_with_bind_to_invalid_interface, s_test_socket_with_bind_to_invalid_interface)

static int s_test_is_network_interface_name_valid(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    ASSERT_FALSE(aws_is_network_interface_name_valid("invalid_name"));
#if defined(AWS_OS_LINUX)
    ASSERT_TRUE(aws_is_network_interface_name_valid("lo"));
#elif !defined(AWS_OS_WINDOWS)
    ASSERT_TRUE(aws_is_network_interface_name_valid("lo0"));
#endif
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_is_network_interface_name_valid, s_test_is_network_interface_name_valid)

#if defined(USE_VSOCK)
static int s_test_vsock_loopback_socket_communication(struct aws_allocator *allocator, void *ctx) {
/* Without vsock loopback it's difficult to test vsock functionality.
 * Also note that having this defined does not guarantee that it's available
 * for use and there's no path to figure out dynamically if it can be used. */
#    if defined(VMADDR_CID_LOCAL)
    (void)ctx;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_VSOCK;

    struct aws_socket_endpoint endpoint = {.address = "1" /* VMADDR_CID_LOCAL */, .port = 8127};

    return s_test_socket(allocator, &options, &endpoint);
#    else
    return 0;
#    endif
}

AWS_TEST_CASE(vsock_loopback_socket_communication, s_test_vsock_loopback_socket_communication)
#endif

static int s_test_udp_socket_communication(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8126};

    return s_test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(udp_socket_communication, s_test_udp_socket_communication)

static int s_test_udp_bind_connect_communication(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint local = {.address = "127.0.0.1", .port = 4242};
    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8126};

    return s_test_socket_ex(allocator, &options, &local, &endpoint);
}
AWS_TEST_CASE(udp_bind_connect_communication, s_test_udp_bind_connect_communication)

struct test_host_callback_data {
    struct aws_host_address a_address;
    struct aws_mutex *mutex;
    bool has_a_address;
    struct aws_condition_variable condition_variable;
    bool invoked;
};

static bool s_test_host_resolved_predicate(void *arg) {
    struct test_host_callback_data *callback_data = arg;

    return callback_data->invoked;
}

static void s_test_host_resolver_shutdown_callback(void *user_data) {
    struct test_host_callback_data *callback_data = user_data;

    aws_mutex_lock(callback_data->mutex);
    callback_data->invoked = true;
    aws_mutex_unlock(callback_data->mutex);

    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static void s_test_host_resolved_test_callback(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {

    (void)resolver;
    (void)host_name;
    (void)err_code;

    struct test_host_callback_data *callback_data = user_data;

    aws_mutex_lock(callback_data->mutex);
    struct aws_host_address *host_address = NULL;

    if (aws_array_list_length(host_addresses) == 1) {
        aws_array_list_get_at_ptr(host_addresses, (void **)&host_address, 0);

        aws_host_address_copy(host_address, &callback_data->a_address);
        callback_data->has_a_address = true;
    }

    callback_data->invoked = true;
    aws_mutex_unlock(callback_data->mutex);
    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static int s_test_connect_timeout(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);
    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 2,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_host_resolution_config resolution_config = {
        .impl = aws_default_dns_resolve, .impl_data = NULL, .max_ttl = 1};

    struct test_host_callback_data host_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    /* This ec2 instance sits in a VPC that makes sure port 81 is black-holed (no TCP SYN should be received). */
    struct aws_string *host_name = aws_string_new_from_c_str(allocator, "ec2-54-158-231-48.compute-1.amazonaws.com");
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_test_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_test_host_resolved_predicate, &host_callback_data);
    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);

    ASSERT_TRUE(host_callback_data.has_a_address);

    struct aws_socket_endpoint endpoint = {.port = 81};
    snprintf(endpoint.address, sizeof(endpoint.address), "%s", aws_string_bytes(host_callback_data.a_address.address));

    aws_string_destroy((void *)host_name);
    aws_host_address_clean_up(&host_callback_data.a_address);

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .connect_invoked = false,
        .error_invoked = false,
        .shutdown_complete = false,
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    aws_socket_set_cleanup_complete_callback(&outgoing, s_local_outgoing_connection_shutdown_complete, &outgoing_args);

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    aws_mutex_unlock(&mutex);
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_TIMEOUT, outgoing_args.last_error);

    aws_socket_set_cleanup_complete_callback(&outgoing, s_local_outgoing_connection_shutdown_complete, &outgoing_args);
    aws_socket_clean_up(&outgoing);
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_outgoing_shutdown_completed_predicate, &outgoing_args));
    aws_mutex_unlock(&mutex);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(connect_timeout, s_test_connect_timeout)

static int s_test_connect_timeout_cancellation(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);
    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 10000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct test_host_callback_data host_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    struct aws_shutdown_callback_options shutdown_options = {
        .shutdown_callback_fn = s_test_host_resolver_shutdown_callback,
        .shutdown_callback_user_data = &host_callback_data,
    };
    shutdown_options.shutdown_callback_fn = s_test_host_resolver_shutdown_callback;

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 2,
        .shutdown_options = &shutdown_options,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_host_resolution_config resolution_config = {
        .impl = aws_default_dns_resolve, .impl_data = NULL, .max_ttl = 1};

    /* This ec2 instance sits in a VPC that makes sure port 81 is black-holed (no TCP SYN should be received). */
    struct aws_string *host_name = aws_string_new_from_c_str(allocator, "ec2-54-158-231-48.compute-1.amazonaws.com");
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_test_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_test_host_resolved_predicate, &host_callback_data);
    host_callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);
    /* wait for shutdown callback */
    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_test_host_resolved_predicate, &host_callback_data);
    aws_mutex_unlock(&mutex);

    ASSERT_TRUE(host_callback_data.has_a_address);

    struct aws_socket_endpoint endpoint = {.port = 81};
    snprintf(endpoint.address, sizeof(endpoint.address), "%s", aws_string_bytes(host_callback_data.a_address.address));

    aws_string_destroy((void *)host_name);
    aws_host_address_clean_up(&host_callback_data.a_address);

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .connect_invoked = false,
        .error_invoked = false,
        .shutdown_complete = false,
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    aws_socket_set_cleanup_complete_callback(&outgoing, s_local_outgoing_connection_shutdown_complete, &outgoing_args);

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    ASSERT_INT_EQUALS(AWS_IO_EVENT_LOOP_SHUTDOWN, outgoing_args.last_error);

    aws_socket_clean_up(&outgoing);
    ASSERT_SUCCESS(aws_mutex_lock(outgoing_args.mutex));
    aws_condition_variable_wait_pred(
        outgoing_args.condition_variable, outgoing_args.mutex, s_outgoing_shutdown_completed_predicate, &outgoing_args);
    ASSERT_SUCCESS(aws_mutex_unlock(outgoing_args.mutex));

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(connect_timeout_cancelation, s_test_connect_timeout_cancellation)

static void s_null_sock_connection(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    struct error_test_args *error_args = (struct error_test_args *)user_data;

    aws_mutex_lock(&error_args->mutex);
    if (error_code) {
        error_args->error_code = error_code;
    }
    aws_socket_close(socket);
    aws_condition_variable_notify_one(&error_args->condition_variable);
    aws_mutex_unlock(&error_args->mutex);
}

static bool s_outgoing_local_error_predicate(void *args) {
    struct error_test_args *test_args = (struct error_test_args *)args;

    return test_args->error_code != 0;
}

static int s_test_outgoing_local_sock_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    struct aws_socket_endpoint endpoint = {.address = ""};

    struct error_test_args args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_invoked = false,
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    aws_socket_set_cleanup_complete_callback(&outgoing, s_socket_error_shutdown_complete, &args);

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_null_sock_connection,
        .user_data = &args};

    int socket_connect_result = aws_socket_connect(&outgoing, &connect_options);
    // As Apple network framework has an async API design, we would not get the error back on connect
    if (aws_socket_get_default_impl_type() != AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {
        ASSERT_FAILS(socket_connect_result);
        ASSERT_TRUE(
            aws_last_error() == AWS_IO_SOCKET_CONNECTION_REFUSED || aws_last_error() == AWS_ERROR_FILE_INVALID_PATH);
    } else {
        ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
        ASSERT_SUCCESS(aws_condition_variable_wait_pred(
            &args.condition_variable, &args.mutex, s_outgoing_local_error_predicate, &args));
        ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));
        ASSERT_TRUE(
            args.error_code == AWS_IO_SOCKET_CONNECTION_REFUSED || args.error_code == AWS_ERROR_FILE_INVALID_PATH);
    }

    aws_socket_clean_up(&outgoing);
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, s_socket_error_shutdown_predicate, &args);
    ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));
    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(outgoing_local_sock_errors, s_test_outgoing_local_sock_errors)

static bool s_outgoing_tcp_error_predicate(void *args) {
    struct error_test_args *test_args = (struct error_test_args *)args;

    return test_args->error_code != 0;
}

static int s_test_outgoing_tcp_sock_error(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 50000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {
        .address = "127.0.0.1",
        .port = 1567,
    };

    struct error_test_args args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_invoked = false,
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    aws_socket_set_cleanup_complete_callback(&outgoing, s_socket_error_shutdown_complete, &args);

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_null_sock_connection,
        .user_data = &args};

    int result = aws_socket_connect(&outgoing, &connect_options);
#ifdef __FreeBSD__
    /**
     * FreeBSD doesn't seem to respect the O_NONBLOCK or SOCK_NONBLOCK flag. It fails immediately when trying to
     * connect to a socket which is not listening. This is flaky and works sometimes, but we don't know why. Since this
     * test does not aim to test for that, skip it in that case.
     */
    if (result != AWS_ERROR_SUCCESS) {
        ASSERT_INT_EQUALS(AWS_IO_SOCKET_CONNECTION_REFUSED, aws_last_error());
        result = AWS_OP_SKIP;
        goto cleanup;
    }
#endif
    ASSERT_SUCCESS(result);
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, s_outgoing_tcp_error_predicate, &args));
    ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CONNECTION_REFUSED, args.error_code);
    result = AWS_OP_SUCCESS;

    goto cleanup; /* to avoid unused label warning on systems other than FreeBSD */
cleanup:
    aws_socket_clean_up(&outgoing);
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &args.condition_variable, &args.mutex, s_socket_error_shutdown_predicate, &args));
    ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));
    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return result;
}
AWS_TEST_CASE(outgoing_tcp_sock_error, s_test_outgoing_tcp_sock_error)

static int s_test_incoming_tcp_sock_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    if (!s_test_running_as_root(allocator)) {
        aws_io_library_init(allocator);

        struct aws_event_loop_group_options elg_options = {
            .loop_count = 1,
        };
        struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
        struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

        ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

        struct aws_socket_options options;
        AWS_ZERO_STRUCT(options);
        options.connect_timeout_ms = 1000;
        options.type = AWS_SOCKET_STREAM;
        options.domain = AWS_SOCKET_IPV4;

        struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = 80,
        };

        struct error_test_args args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT,
            .shutdown_invoked = false,
        };

        struct aws_socket incoming;
        ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options));

        struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
        ASSERT_ERROR(AWS_ERROR_NO_PERMISSION, aws_socket_bind(&incoming, &socket_bind_options));

        aws_socket_set_cleanup_complete_callback(&incoming, s_socket_error_shutdown_complete, &args);

        aws_socket_clean_up(&incoming);
        ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
        ASSERT_SUCCESS(aws_condition_variable_wait_pred(
            &args.condition_variable, &args.mutex, s_socket_error_shutdown_predicate, &args));
        ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));

        aws_event_loop_group_release(el_group);
        aws_io_library_clean_up();
    }
    return 0;
}

AWS_TEST_CASE(incoming_tcp_sock_errors, s_test_incoming_tcp_sock_errors)

static int s_test_incoming_duplicate_tcp_bind_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);
    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {
        .address = "127.0.0.1",
        .port = 30123,
    };

    struct aws_socket incoming;
    ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&incoming, &socket_bind_options));
    ASSERT_SUCCESS(aws_socket_listen(&incoming, 1024));
    struct aws_socket duplicate_bind;
    ASSERT_SUCCESS(aws_socket_init(&duplicate_bind, allocator, &options));
    ASSERT_ERROR(AWS_IO_SOCKET_ADDRESS_IN_USE, aws_socket_bind(&duplicate_bind, &socket_bind_options));

    aws_socket_close(&duplicate_bind);
    aws_socket_clean_up(&duplicate_bind);
    aws_socket_close(&incoming);
    aws_socket_clean_up(&incoming);
    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();
    return 0;
}

AWS_TEST_CASE(incoming_duplicate_tcp_bind_errors, s_test_incoming_duplicate_tcp_bind_errors)

struct nw_socket_bind_args {
    struct aws_socket *incoming;
    struct aws_socket *listener;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    bool start_listening;
    bool incoming_invoked;
    bool error_invoked;
    bool shutdown_complete;
};

static void s_bind_args_shutdown_complete(void *user_data) {
    struct nw_socket_bind_args *bind_args = (struct nw_socket_bind_args *)user_data;

    aws_mutex_lock(bind_args->mutex);
    bind_args->shutdown_complete = true;
    aws_mutex_unlock(bind_args->mutex);
    aws_condition_variable_notify_one(bind_args->condition_variable);
}

static bool s_bind_args_shutdown_completed_predicate(void *arg) {
    struct nw_socket_bind_args *bind_args = arg;

    return bind_args->shutdown_complete;
}

static bool s_bind_args_start_listening_predicate(void *arg) {
    struct nw_socket_bind_args *bind_args = arg;

    return bind_args->start_listening;
}

static void s_local_listener_incoming_destroy_listener_bind(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    (void)socket;
    struct nw_socket_bind_args *listener_args = (struct nw_socket_bind_args *)user_data;
    aws_mutex_lock(listener_args->mutex);

    if (!error_code) {
        listener_args->incoming = new_socket;
        listener_args->incoming_invoked = true;
    } else {
        listener_args->error_invoked = true;
    }
    if (new_socket)
        aws_socket_clean_up(new_socket);
    aws_condition_variable_notify_one(listener_args->condition_variable);
    aws_mutex_unlock(listener_args->mutex);
}

static void s_local_listener_start_accept(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    struct nw_socket_bind_args *listener_args = (struct nw_socket_bind_args *)user_data;
    aws_mutex_lock(listener_args->mutex);

    if (!error_code) {
        listener_args->start_listening = true;
    } else {
        listener_args->error_invoked = true;
    }
    aws_condition_variable_notify_one(listener_args->condition_variable);
    aws_mutex_unlock(listener_args->mutex);
}

/* Ensure that binding to port 0 results in OS assigning a port */
static int s_test_bind_on_zero_port(
    struct aws_allocator *allocator,
    enum aws_socket_type sock_type,
    enum aws_socket_domain sock_domain,
    const char *address) {

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = sock_type;
    options.domain = sock_domain;

    struct aws_socket_endpoint endpoint = {
        .port = 0 /* important: must be 0 for this test */,
    };
    strncpy(endpoint.address, address, sizeof(endpoint.address));

    struct aws_socket incoming;
    ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options));

    /* ensure address query fails if socket isn't bound yet */
    struct aws_socket_endpoint local_address1;
    ASSERT_FAILS(aws_socket_get_bound_address(&incoming, &local_address1));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&incoming, &socket_bind_options));

    ASSERT_SUCCESS(aws_socket_get_bound_address(&incoming, &local_address1));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    struct nw_socket_bind_args listener_args = {
        .incoming = NULL,
        .listener = &incoming,
        .incoming_invoked = false,
        .error_invoked = false,
        .mutex = &mutex,
        .condition_variable = &condition_variable,
    };

    if (aws_socket_get_default_impl_type() == AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {

        ASSERT_SUCCESS(aws_socket_listen(&incoming, 1024));
        struct aws_socket_listener_options listener_options = {
            .on_accept_result = s_local_listener_incoming_destroy_listener_bind,
            .on_accept_result_user_data = &listener_args,
            .on_accept_start = s_local_listener_start_accept,
            .on_accept_start_user_data = &listener_args};

        ASSERT_SUCCESS(aws_socket_start_accept(&incoming, event_loop, listener_options));

        // Apple Dispatch Queue requires a listener to be ready before it can get the assigned port. We wait until the
        // port is back.
        ASSERT_SUCCESS(aws_mutex_lock(listener_args.mutex));
        ASSERT_SUCCESS(aws_condition_variable_wait_pred(
            listener_args.condition_variable,
            listener_args.mutex,
            s_bind_args_start_listening_predicate,
            &listener_args));
        ASSERT_SUCCESS(aws_mutex_unlock(listener_args.mutex));

        ASSERT_SUCCESS(aws_socket_get_bound_address(&incoming, &local_address1));

    } else {
        if (sock_type != AWS_SOCKET_DGRAM) {
            ASSERT_SUCCESS(aws_socket_listen(&incoming, 1024));
        }
    }
    ASSERT_TRUE(local_address1.port > 0);
    ASSERT_STR_EQUALS(address, local_address1.address);

    /* ensure that querying again gets the same results */
    struct aws_socket_endpoint local_address2;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&incoming, &local_address2));
    ASSERT_INT_EQUALS(local_address1.port, local_address2.port);
    ASSERT_STR_EQUALS(local_address1.address, local_address2.address);

    aws_socket_set_cleanup_complete_callback(&incoming, s_bind_args_shutdown_complete, &listener_args);
    aws_socket_close(&incoming);
    aws_socket_clean_up(&incoming);

    ASSERT_SUCCESS(aws_mutex_lock(listener_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        listener_args.condition_variable,
        listener_args.mutex,
        s_bind_args_shutdown_completed_predicate,
        &listener_args));
    ASSERT_SUCCESS(aws_mutex_unlock(listener_args.mutex));
    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();
    return 0;
}

static int s_bind_on_zero_port_tcp_ipv4(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_bind_on_zero_port(allocator, AWS_SOCKET_STREAM, AWS_SOCKET_IPV4, "127.0.0.1");
}
AWS_TEST_CASE(bind_on_zero_port_tcp_ipv4, s_bind_on_zero_port_tcp_ipv4)

static int s_bind_on_zero_port_udp_ipv4(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_bind_on_zero_port(allocator, AWS_SOCKET_DGRAM, AWS_SOCKET_IPV4, "127.0.0.1");
}
AWS_TEST_CASE(bind_on_zero_port_udp_ipv4, s_bind_on_zero_port_udp_ipv4)

static int s_test_incoming_udp_sock_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    if (!s_test_running_as_root(allocator)) {

        aws_io_library_init(allocator);

        struct aws_event_loop_group_options elg_options = {
            .loop_count = 1,
        };
        struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
        struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

        ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

        struct aws_socket_options options;
        AWS_ZERO_STRUCT(options);
        options.connect_timeout_ms = 1000;
        options.type = AWS_SOCKET_DGRAM;
        options.domain = AWS_SOCKET_IPV4;

        /* hit a endpoint that will not send me a SYN packet. */
        struct aws_socket_endpoint endpoint = {
            .address = "127.0",
            .port = 80,
        };

        struct aws_socket incoming;
        ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options));
        struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
        ASSERT_FAILS(aws_socket_bind(&incoming, &socket_bind_options));
        int error = aws_last_error();
        ASSERT_TRUE(AWS_IO_SOCKET_INVALID_ADDRESS == error || AWS_ERROR_NO_PERMISSION == error);

        aws_socket_clean_up(&incoming);
        aws_event_loop_group_release(el_group);
        aws_io_library_clean_up();
    }
    return 0;
}

AWS_TEST_CASE(incoming_udp_sock_errors, s_test_incoming_udp_sock_errors)

static void s_on_null_readable_notification(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)error_code;
    (void)user_data;
}

static int s_test_wrong_thread_read_write_fails(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {
        .address = "127.0.0.1",
        .port = 50000,
    };

    struct aws_socket socket;
    ASSERT_SUCCESS(aws_socket_init(&socket, allocator, &options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    aws_socket_bind(&socket, &socket_bind_options);
    aws_socket_assign_to_event_loop(&socket, event_loop);
    aws_socket_subscribe_to_readable_events(&socket, s_on_null_readable_notification, NULL);
    size_t amount_read = 0;
    ASSERT_ERROR(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY, aws_socket_read(&socket, NULL, &amount_read));
    ASSERT_ERROR(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY, aws_socket_write(&socket, NULL, NULL, NULL));

    struct aws_mutex mutex = AWS_MUTEX_INIT;

    struct socket_io_args io_args;
    io_args.socket = &socket;
    io_args.close_completed = false;
    io_args.condition_variable = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    io_args.mutex = &mutex;

    struct aws_task close_task = {
        .fn = s_socket_close_task,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    aws_mutex_unlock(&mutex);

    aws_socket_clean_up(&socket);
    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(wrong_thread_read_write_fails, s_test_wrong_thread_read_write_fails)

static void s_test_destroy_socket_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct aws_socket *socket = arg;
    aws_socket_clean_up(socket);
}

static int s_cleanup_before_connect_or_timeout_doesnt_explode(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 2,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_host_resolution_config resolution_config = {
        .impl = aws_default_dns_resolve, .impl_data = NULL, .max_ttl = 1};

    struct test_host_callback_data host_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    /* This ec2 instance sits in a VPC that makes sure port 81 is black-holed (no TCP SYN should be received). */
    struct aws_string *host_name = aws_string_new_from_c_str(allocator, "ec2-54-158-231-48.compute-1.amazonaws.com");
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_test_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_test_host_resolved_predicate, &host_callback_data);
    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);

    ASSERT_TRUE(host_callback_data.has_a_address);

    struct aws_socket_endpoint endpoint = {.port = 81};
    snprintf(endpoint.address, sizeof(endpoint.address), "%s", aws_string_bytes(host_callback_data.a_address.address));

    aws_string_destroy((void *)host_name);
    aws_host_address_clean_up(&host_callback_data.a_address);

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .connect_invoked = false,
        .error_invoked = false,
        .shutdown_complete = false,
    };

    struct error_test_args shutdown_args = {
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_invoked = false,
    };

    struct aws_socket outgoing;

    struct aws_task destroy_task = {
        .fn = s_test_destroy_socket_task,
        .arg = &outgoing,
    };

    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));
    aws_socket_set_cleanup_complete_callback(&outgoing, s_socket_error_shutdown_complete, &shutdown_args);

    aws_event_loop_schedule_task_now(event_loop, &destroy_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_ERROR(
        AWS_ERROR_COND_VARIABLE_TIMED_OUT,
        aws_condition_variable_wait_for(
            &condition_variable,
            &mutex,
            aws_timestamp_convert(options.connect_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL)));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_FALSE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_socket_error_shutdown_predicate, &shutdown_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    return 0;
}

AWS_TEST_CASE(cleanup_before_connect_or_timeout_doesnt_explode, s_cleanup_before_connect_or_timeout_doesnt_explode)

static void s_local_listener_incoming_destroy_listener(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    (void)socket;
    struct local_listener_args *listener_args = (struct local_listener_args *)user_data;
    aws_mutex_lock(listener_args->mutex);

    if (!error_code) {
        listener_args->incoming = new_socket;
        listener_args->incoming_invoked = true;
    } else {
        listener_args->error_invoked = true;
    }

    if (socket) {
        aws_socket_clean_up(socket);
    }
    aws_condition_variable_notify_one(listener_args->condition_variable);
    aws_mutex_unlock(listener_args->mutex);
}

static int s_cleanup_in_accept_doesnt_explode(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .incoming = NULL,
        .incoming_invoked = false,
        .error_invoked = false,
        .shutdown_complete = false,
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8129};

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &socket_bind_options));

    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    aws_socket_set_cleanup_complete_callback(&listener, s_local_listener_shutdown_complete, &listener_args);
#endif
    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_local_listener_incoming_destroy_listener, .on_accept_result_user_data = &listener_args};

    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    ASSERT_TRUE(listener_args.incoming_invoked);
    ASSERT_FALSE(listener_args.error_invoked);
    ASSERT_TRUE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(options.domain, listener_args.incoming->options.domain);
    ASSERT_INT_EQUALS(options.type, listener_args.incoming->options.type);

    struct socket_io_args io_args = {
        .socket = &outgoing,
        .to_write = NULL,
        .to_read = NULL,
        .read_data = NULL,
        .mutex = &mutex,
        .amount_read = 0,
        .amount_written = 0,
        .error_code = 0,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .close_completed = false,
        .shutdown_complete = false,
    };

    struct aws_task close_task = {
        .fn = s_socket_close_task,
        .arg = &io_args,
    };

    if (listener_args.incoming) {
        io_args.socket = listener_args.incoming;
        io_args.close_completed = false;

#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
        aws_socket_set_cleanup_complete_callback(io_args.socket, s_socket_shutdown_complete_fn, &io_args);
        io_args.shutdown_complete = false;
#endif
        aws_socket_assign_to_event_loop(io_args.socket, event_loop);
        aws_event_loop_schedule_task_now(event_loop, &close_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

        aws_socket_clean_up(io_args.socket);
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
#endif
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    aws_socket_set_cleanup_complete_callback(io_args.socket, s_socket_shutdown_complete_fn, &io_args);
    io_args.close_completed = false;
    io_args.shutdown_complete = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    aws_socket_clean_up(&outgoing);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(cleanup_in_accept_doesnt_explode, s_cleanup_in_accept_doesnt_explode)

static void s_on_written_destroy(struct aws_socket *socket, int error_code, size_t amount_written, void *user_data) {
    (void)socket;
    struct socket_io_args *write_args = user_data;
    aws_mutex_lock(write_args->mutex);
    write_args->error_code = error_code;
    write_args->amount_written = amount_written;
    if (socket) {
        aws_socket_clean_up(socket);
    }
    aws_condition_variable_notify_one(&write_args->condition_variable);
    aws_mutex_unlock(write_args->mutex);
}

static bool s_write_completed_predicate_destroy(void *arg) {
    struct socket_io_args *io_args = arg;

    return io_args->amount_written || io_args->error_code;
}

static void s_write_task_destroy(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct socket_io_args *io_args = args;
    aws_socket_write(io_args->socket, io_args->to_write, s_on_written_destroy, io_args);
}

static int s_cleanup_in_write_cb_doesnt_explode(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .incoming = NULL,
        .incoming_invoked = false,
        .error_invoked = false,
        .shutdown_complete = false,
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8130};

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &socket_bind_options));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_local_listener_incoming, .on_accept_result_user_data = &listener_args};
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    ASSERT_TRUE(listener_args.incoming_invoked);
    ASSERT_FALSE(listener_args.error_invoked);
    struct aws_socket *server_sock = listener_args.incoming;
    ASSERT_TRUE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(options.domain, listener_args.incoming->options.domain);
    ASSERT_INT_EQUALS(options.type, listener_args.incoming->options.type);

    ASSERT_SUCCESS(aws_socket_assign_to_event_loop(server_sock, event_loop));
    aws_socket_subscribe_to_readable_events(server_sock, s_on_readable, NULL);
    aws_socket_subscribe_to_readable_events(&outgoing, s_on_readable, NULL);

    /* now test the read and write across the connection. */
    const char read_data[] = "I'm a little teapot";
    char write_data[sizeof(read_data)] = {0};

    struct aws_byte_buf read_buffer = aws_byte_buf_from_array((const uint8_t *)read_data, sizeof(read_data));
    struct aws_byte_buf write_buffer = aws_byte_buf_from_array((const uint8_t *)write_data, sizeof(write_data));
    write_buffer.len = 0;

    struct aws_byte_cursor read_cursor = aws_byte_cursor_from_buf(&read_buffer);

    struct socket_io_args io_args = {
        .socket = &outgoing,
        .to_write = &read_cursor,
        .to_read = &read_buffer,
        .read_data = &write_buffer,
        .mutex = &mutex,
        .amount_read = 0,
        .amount_written = 0,
        .error_code = 0,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .close_completed = false,
        .shutdown_complete = false,
    };

#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    aws_socket_set_cleanup_complete_callback(io_args.socket, s_socket_shutdown_complete_fn, &io_args);
#endif

    struct aws_task write_task = {
        .fn = s_write_task_destroy,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &write_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &io_args.condition_variable, &mutex, s_write_completed_predicate_destroy, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    memset((void *)write_data, 0, sizeof(write_data));
    write_buffer.len = 0;

    io_args.error_code = 0;
    io_args.amount_written = 0;
    io_args.socket = server_sock;
    io_args.shutdown_complete = false;
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    aws_socket_set_cleanup_complete_callback(io_args.socket, s_socket_shutdown_complete_fn, &io_args);
#endif
    aws_event_loop_schedule_task_now(event_loop, &write_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_shutdown_completed_predicate, &io_args);
#endif
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);
    aws_mem_release(allocator, server_sock);

#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    aws_socket_set_cleanup_complete_callback(&listener, s_local_listener_shutdown_complete, &listener_args);
#endif
    aws_socket_clean_up(&listener);
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        listener_args.condition_variable, &mutex, s_local_listener_shutdown_completed_predicate, &listener_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
#endif

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(cleanup_in_write_cb_doesnt_explode, s_cleanup_in_write_cb_doesnt_explode)

/* stuff for the sock_write_cb_is_async test */
enum async_role {
    ASYNC_ROLE_A_CALLBACK_WRITES_D,
    ASYNC_ROLE_B_CALLBACK_CLEANS_UP_SOCKET,
    ASYNC_ROLE_C_IS_LAST_FROM_INITIAL_BATCH_OF_WRITES,
    ASYNC_ROLE_D_GOT_WRITTEN_VIA_CALLBACK,
    ASYNC_ROLE_COUNT
};

static struct async_test_args {
    struct aws_allocator *allocator;
    struct aws_event_loop *event_loop;
    struct aws_socket *write_socket;
    struct aws_socket *read_socket;
    bool currently_writing;
    enum async_role next_expected_callback;
    int read_error;

    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    bool write_tasks_complete;
    bool read_tasks_complete;
} g_async_tester;

static bool s_async_tasks_complete_pred(void *arg) {
    (void)arg;
    return g_async_tester.write_tasks_complete && g_async_tester.read_tasks_complete;
}

/* read until socket gets hung up on */
static void s_async_read_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)args;
    (void)status;
    uint8_t buf_storage[100];
    AWS_ZERO_ARRAY(buf_storage);

    struct aws_byte_buf buf = aws_byte_buf_from_array(buf_storage, sizeof(buf_storage));
    while (true) {
        size_t amount_read = 0;
        buf.len = 0;
        if (aws_socket_read(g_async_tester.read_socket, &buf, &amount_read)) {
            /* reschedule task to try reading more later */
            /*
             * For Apple Network Framework (dispatch queue), the read error would not directly returned from
             * aws_socket_read, but from the callback, therefore, we validate the g_async_tester.read_error
             * returned from the callback
             */
            if (!g_async_tester.read_error && AWS_IO_READ_WOULD_BLOCK == aws_last_error()) {
                aws_event_loop_schedule_task_now(g_async_tester.event_loop, task);
                break;
            }

            /* other end must have hung up. clean up and signal completion */
            aws_socket_clean_up(g_async_tester.read_socket);
            aws_mem_release(g_async_tester.allocator, g_async_tester.read_socket);

            aws_mutex_lock(g_async_tester.mutex);
            g_async_tester.read_tasks_complete = true;
            aws_mutex_unlock(g_async_tester.mutex);
            aws_condition_variable_notify_all(g_async_tester.condition_variable);
            break;
        }
    }
}

static void s_async_write_completion(struct aws_socket *socket, int error_code, size_t bytes_written, void *user_data) {
    enum async_role role = *(enum async_role *)user_data;
    aws_mem_release(g_async_tester.allocator, user_data);

    /* ensure callback is not firing synchronously from within aws_socket_write() */
    AWS_FATAL_ASSERT(!g_async_tester.currently_writing);

    /* ensure callbacks arrive in order */
    AWS_FATAL_ASSERT(g_async_tester.next_expected_callback == role);
    g_async_tester.next_expected_callback++;

    switch (role) {
        case ASYNC_ROLE_A_CALLBACK_WRITES_D: {
            AWS_FATAL_ASSERT(0 == error_code);
            AWS_FATAL_ASSERT(1 == bytes_written);
            g_async_tester.currently_writing = true;
            struct aws_byte_cursor data = aws_byte_cursor_from_c_str("D");
            enum async_role *d_role = aws_mem_acquire(g_async_tester.allocator, sizeof(enum async_role));
            *d_role = ASYNC_ROLE_D_GOT_WRITTEN_VIA_CALLBACK;
            AWS_FATAL_ASSERT(0 == aws_socket_write(socket, &data, s_async_write_completion, d_role));
            g_async_tester.currently_writing = false;
            break;
        }
        case ASYNC_ROLE_B_CALLBACK_CLEANS_UP_SOCKET:
            AWS_FATAL_ASSERT(0 == error_code);
            AWS_FATAL_ASSERT(1 == bytes_written);
            aws_socket_clean_up(socket);
            break;
        case ASYNC_ROLE_C_IS_LAST_FROM_INITIAL_BATCH_OF_WRITES:
            /* C might succeed or fail (since socket killed after B completes), either is valid */
            break;
        case ASYNC_ROLE_D_GOT_WRITTEN_VIA_CALLBACK:
            /* write tasks complete! */
            aws_mutex_lock(g_async_tester.mutex);
            g_async_tester.write_tasks_complete = true;
            aws_mutex_unlock(g_async_tester.mutex);
            aws_condition_variable_notify_all(g_async_tester.condition_variable);
            break;
        default:
            AWS_FATAL_ASSERT(0);
    }
}

static void s_async_write_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    (void)args;
    (void)status;

    g_async_tester.currently_writing = true;

    struct aws_byte_cursor data = aws_byte_cursor_from_c_str("A");
    enum async_role *role = aws_mem_acquire(g_async_tester.allocator, sizeof(enum async_role));
    *role = ASYNC_ROLE_A_CALLBACK_WRITES_D;
    AWS_FATAL_ASSERT(0 == aws_socket_write(g_async_tester.write_socket, &data, s_async_write_completion, role));

    data = aws_byte_cursor_from_c_str("B");
    role = aws_mem_acquire(g_async_tester.allocator, sizeof(enum async_role));
    *role = ASYNC_ROLE_B_CALLBACK_CLEANS_UP_SOCKET;
    AWS_FATAL_ASSERT(0 == aws_socket_write(g_async_tester.write_socket, &data, s_async_write_completion, role));

    data = aws_byte_cursor_from_c_str("C");
    role = aws_mem_acquire(g_async_tester.allocator, sizeof(enum async_role));
    *role = ASYNC_ROLE_C_IS_LAST_FROM_INITIAL_BATCH_OF_WRITES;
    AWS_FATAL_ASSERT(0 == aws_socket_write(g_async_tester.write_socket, &data, s_async_write_completion, role));

    g_async_tester.currently_writing = false;
}

static void s_on_readable_return(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)error_code;
    struct async_test_args *async_tester = user_data;
    if (error_code) {
        async_tester->read_error = error_code;
    }
}

/**
 * aws_socket_write()'s completion callback MUST fire asynchronously.
 * Otherwise, we can get multiple write() calls in the same callstack, which
 * leads to esoteric bugs (https://github.com/aws/aws-iot-device-sdk-cpp-v2/issues/194).
 */
static int s_sock_write_cb_is_async(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* set up server (read) and client (write) sockets */
    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {
        .loop_count = 1,
    };
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .incoming = NULL,
        .incoming_invoked = false,
        .error_invoked = false,
        .shutdown_complete = false,
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;
    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);
    aws_socket_endpoint_init_local_address_for_test(&endpoint);

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &socket_bind_options));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_local_listener_incoming, .on_accept_result_user_data = &listener_args};
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    ASSERT_TRUE(listener_args.incoming_invoked);
    ASSERT_FALSE(listener_args.error_invoked);
    struct aws_socket *server_sock = listener_args.incoming;
    ASSERT_TRUE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(options.domain, listener_args.incoming->options.domain);
    ASSERT_INT_EQUALS(options.type, listener_args.incoming->options.type);

    ASSERT_SUCCESS(aws_socket_assign_to_event_loop(server_sock, event_loop));
    aws_socket_subscribe_to_readable_events(server_sock, s_on_readable_return, &g_async_tester);
    aws_socket_subscribe_to_readable_events(&outgoing, s_on_readable, NULL);

    /* set up g_async_tester */
    g_async_tester.allocator = allocator;
    g_async_tester.event_loop = event_loop;
    g_async_tester.write_socket = &outgoing;
    g_async_tester.read_socket = server_sock;
    g_async_tester.mutex = &mutex;
    g_async_tester.condition_variable = &condition_variable;

    /* kick off writer and reader tasks */
    struct aws_task writer_task;
    aws_task_init(&writer_task, s_async_write_task, NULL, "async_test_write_task");
    aws_event_loop_schedule_task_now(event_loop, &writer_task);

    struct aws_task reader_task;
    aws_task_init(&reader_task, s_async_read_task, NULL, "async_test_read_task");
    aws_event_loop_schedule_task_now(event_loop, &reader_task);

    /* wait for tasks to complete */
    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(&condition_variable, &mutex, s_async_tasks_complete_pred, NULL);
    aws_mutex_unlock(&mutex);

    aws_socket_set_cleanup_complete_callback(&listener, s_local_listener_shutdown_complete, &listener_args);
    /* cleanup */
    aws_socket_clean_up(&listener);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_local_listener_shutdown_completed_predicate, &listener_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(sock_write_cb_is_async, s_sock_write_cb_is_async)

#ifdef _WIN32
static int s_local_socket_pipe_connected_race(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .incoming = NULL,
        .incoming_invoked = false,
        .error_invoked = false,
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);
    aws_socket_endpoint_init_local_address_for_test(&endpoint);

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options));

    struct aws_socket_bind_options socket_bind_options = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &socket_bind_options));

    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));

    /* do the connect after the named pipe has been created (in the bind call), but before the connect named pipe call
       has been made in start accept. This will ensure IOCP does what we think it does. */
    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    struct aws_socket_connect_options connect_options = {
        .remote_endpoint = &endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_local_outgoing_connection,
        .user_data = &outgoing_args};

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &connect_options));

    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_local_listener_incoming, .on_accept_result_user_data = &listener_args};
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    aws_mutex_unlock(&mutex);

    struct aws_socket *server_sock = &listener;

    ASSERT_TRUE(listener_args.incoming_invoked);
    ASSERT_FALSE(listener_args.error_invoked);
    server_sock = listener_args.incoming;
    ASSERT_TRUE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(options.domain, listener_args.incoming->options.domain);
    ASSERT_INT_EQUALS(options.type, listener_args.incoming->options.type);

    struct socket_io_args io_args = {
        .socket = &outgoing,
        .to_write = NULL,
        .to_read = NULL,
        .read_data = NULL,
        .mutex = &mutex,
        .amount_read = 0,
        .amount_written = 0,
        .error_code = 0,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .close_completed = false,
    };

    struct aws_task close_task = {
        .fn = s_socket_close_task,
        .arg = &io_args,
    };

    if (listener_args.incoming) {
        io_args.socket = listener_args.incoming;
        io_args.close_completed = false;
        aws_event_loop_schedule_task_now(event_loop, &close_task);
        aws_mutex_lock(&mutex);
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
        aws_mutex_unlock(&mutex);

        aws_socket_clean_up(listener_args.incoming);
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    aws_mutex_unlock(&mutex);

    aws_socket_clean_up(&outgoing);

    io_args.socket = &listener;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    aws_mutex_unlock(&mutex);

    aws_socket_clean_up(&listener);

    aws_event_loop_destroy(event_loop);

    return 0;
}
AWS_TEST_CASE(local_socket_pipe_connected_race, s_local_socket_pipe_connected_race)

#endif

static int s_test_socket_validate_port(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* IPv4 - 16bit port, only bind can use 0 */
    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(80, AWS_SOCKET_IPV4));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(80, AWS_SOCKET_IPV4));

    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_connect(0, AWS_SOCKET_IPV4));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(0, AWS_SOCKET_IPV4));

    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_connect(0xFFFFFFFF, AWS_SOCKET_IPV4));
    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_bind(0xFFFFFFFF, AWS_SOCKET_IPV4));

    /* IPv6 - 16bit port, only bind can use 0 */
    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(80, AWS_SOCKET_IPV6));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(80, AWS_SOCKET_IPV6));

    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_connect(0, AWS_SOCKET_IPV6));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(0, AWS_SOCKET_IPV6));

    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_connect(0xFFFFFFFF, AWS_SOCKET_IPV6));
    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_bind(0xFFFFFFFF, AWS_SOCKET_IPV6));

    /* VSOCK - 32bit port, only bind can use VMADDR_PORT_ANY (-1U) */
    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(80, AWS_SOCKET_VSOCK));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(80, AWS_SOCKET_VSOCK));

    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(0, AWS_SOCKET_VSOCK));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(0, AWS_SOCKET_VSOCK));

    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(0x7FFFFFFF, AWS_SOCKET_VSOCK));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(0x7FFFFFFF, AWS_SOCKET_VSOCK));

    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_connect((uint32_t)-1, AWS_SOCKET_VSOCK));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind((uint32_t)-1, AWS_SOCKET_VSOCK));

    /* LOCAL - ignores port */
    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(0, AWS_SOCKET_LOCAL));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(0, AWS_SOCKET_LOCAL));
    ASSERT_SUCCESS(aws_socket_validate_port_for_connect(80, AWS_SOCKET_LOCAL));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind(80, AWS_SOCKET_LOCAL));
    ASSERT_SUCCESS(aws_socket_validate_port_for_connect((uint32_t)-1, AWS_SOCKET_LOCAL));
    ASSERT_SUCCESS(aws_socket_validate_port_for_bind((uint32_t)-1, AWS_SOCKET_LOCAL));

    /* invalid domain should fail */
    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_connect(80, (enum aws_socket_domain)(-1)));
    ASSERT_ERROR(AWS_IO_SOCKET_INVALID_ADDRESS, aws_socket_validate_port_for_bind(80, (enum aws_socket_domain)(-1)));

    return 0;
}
AWS_TEST_CASE(socket_validate_port, s_test_socket_validate_port)

static int s_test_parse_ipv4_valid_addresses(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct {
        const char *input;
        uint32_t expected_network_order;
    } test_cases[] = {
        {"127.0.0.1", htonl(0x7F000001)},       /* localhost */
        {"0.0.0.0", htonl(0x00000000)},         /* any address */
        {"255.255.255.255", htonl(0xFFFFFFFF)}, /* broadcast */
        {"192.168.1.1", htonl(0xC0A80101)},     /* common private IP */
        {"10.0.0.1", htonl(0x0A000001)},        /* private IP */
        {"172.16.0.1", htonl(0xAC100001)},      /* private IP */
        {"8.8.8.8", htonl(0x08080808)},         /* Google DNS */
        {"1.2.3.4", htonl(0x01020304)},         /* simple test case */
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(test_cases); i++) {
        uint32_t result;
        struct aws_string *addr_str = aws_string_new_from_c_str(allocator, test_cases[i].input);
        ASSERT_SUCCESS(aws_parse_ipv4_address(addr_str, &result));
        ASSERT_INT_EQUALS(test_cases[i].expected_network_order, result, "Failed for %s", test_cases[i].input);
        aws_string_destroy(addr_str);
    }

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(parse_ipv4_valid_addresses, s_test_parse_ipv4_valid_addresses)

static int s_test_parse_ipv4_invalid_addresses(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *invalid_addresses[] = {
        "",                  /* empty string */
        "256.1.1.1",         /* octet > 255 */
        "1.1.1",             /* too few octets */
        "1.1.1.1.1",         /* too many octets */
        "1.1.1.a",           /* non-numeric */
        "1..1.1",            /* empty octet */
        "192.168.1.-1",      /* negative number */
        "not.an.ip.address", /* clearly not an IP */
        "2001:db8::1",       /* IPv6 address */
    };

    for (size_t i = 0; i < AWS_ARRAY_SIZE(invalid_addresses); i++) {
        uint32_t result;
        struct aws_string *addr_str = aws_string_new_from_c_str(allocator, invalid_addresses[i]);
        ASSERT_FAILS(aws_parse_ipv4_address(addr_str, &result), "Failed for %s", invalid_addresses[i]);
        ASSERT_INT_EQUALS(AWS_IO_SOCKET_INVALID_ADDRESS, aws_last_error(), "Wrong error for %s", invalid_addresses[i]);
        aws_string_destroy(addr_str);
    }

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(parse_ipv4_invalid_addresses, s_test_parse_ipv4_invalid_addresses)

static int s_test_parse_ipv6_valid_addresses(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct {
        const char *input;
        uint8_t expected[16];
    } test_cases[] = {
        // {"::1", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}, /* loopback */
        {"::", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, /* any address */
        {"2001:db8:85a3::8a2e:370:7334",
         {0x20,
          0x01,
          0x0d,
          0xb8,
          0x85,
          0xa3,
          0x00,
          0x00,
          0x00,
          0x00,
          0x8a,
          0x2e,
          0x03,
          0x70,
          0x73,
          0x34}},                                                                           /* compressed
                                                                                             */
        {"::ffff:192.168.1.1", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1}}, /* IPv4-mapped */
        {"fe80::1", {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},                /* link-local */
    };

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 16);
    for (size_t i = 0; i < AWS_ARRAY_SIZE(test_cases); i++) {
        struct aws_string *addr_str = aws_string_new_from_c_str(allocator, test_cases[i].input);
        ASSERT_SUCCESS(aws_parse_ipv6_address(addr_str, &result), "Failed for %s", test_cases[i].input);
        struct aws_byte_cursor expected = aws_byte_cursor_from_array(test_cases[i].expected, 16);
        ASSERT_TRUE(aws_byte_cursor_eq_byte_buf(&expected, &result));
        aws_string_destroy(addr_str);
        aws_byte_buf_reset(&result, false);
    }
    aws_byte_buf_clean_up(&result);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(parse_ipv6_valid_addresses, s_test_parse_ipv6_valid_addresses)

static int s_test_parse_ipv6_invalid_addresses(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *invalid_addresses[] = {
        "",                                             /* empty string */
        ":::",                                          /* too many colons */
        "2001:db8:85a3::8a2e::7334",                    /* multiple :: */
        "2001:db8:85a3:0000:0000:8a2e:0370:7334:extra", /* too many groups */
        "2001:db8:85a3:0000:0000:8a2e:0370:733g",       /* invalid hex digit */
        "192.168.1.1",                                  /* IPv4 address */
        "not:an:ipv6:address",                          /* clearly not IPv6 */
        "gggg::1",                                      /* invalid hex characters */
    };

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 16);
    for (size_t i = 0; i < AWS_ARRAY_SIZE(invalid_addresses); i++) {
        struct aws_string *addr_str = aws_string_new_from_c_str(allocator, invalid_addresses[i]);
        ASSERT_FAILS(aws_parse_ipv6_address(addr_str, &result), "Failed for %s", invalid_addresses[i]);
        ASSERT_INT_EQUALS(AWS_IO_SOCKET_INVALID_ADDRESS, aws_last_error(), "Wrong error for %s", invalid_addresses[i]);
        aws_string_destroy(addr_str);
        aws_byte_buf_reset(&result, false);
    }
    aws_byte_buf_clean_up(&result);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(parse_ipv6_invalid_addresses, s_test_parse_ipv6_invalid_addresses)

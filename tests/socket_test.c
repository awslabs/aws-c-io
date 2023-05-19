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
};

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

struct socket_io_args {
    struct aws_socket *socket;
    struct aws_byte_cursor *to_write;
    struct aws_byte_buf *to_read;
    struct aws_byte_buf *read_data;
    size_t amount_written;
    size_t amount_read;
    int error_code;
    bool close_completed;
    struct aws_mutex *mutex;
    struct aws_condition_variable condition_variable;
};

static void s_on_written(struct aws_socket *socket, int error_code, size_t amount_written, void *user_data) {
    (void)socket;
    struct socket_io_args *write_args = user_data;
    aws_mutex_lock(write_args->mutex);
    write_args->error_code = error_code;
    write_args->amount_written = amount_written;
    aws_mutex_unlock(write_args->mutex);
    aws_condition_variable_notify_one(&write_args->condition_variable);
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
                continue;
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

    err = aws_socket_bind(&socket, &endpoint);
    err |= aws_socket_listen(&socket, 1024);
    bool is_root = !err;
    aws_socket_clean_up(&socket);
    return is_root;
}

static int s_test_socket_ex(
    struct aws_allocator *allocator,
    struct aws_socket_options *options,
    struct aws_socket_endpoint *local,
    struct aws_socket_endpoint *endpoint) {
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

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, options));

    ASSERT_SUCCESS(aws_socket_bind(&listener, endpoint));

    struct aws_socket_endpoint bound_endpoint;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&listener, &bound_endpoint));
    ASSERT_INT_EQUALS(endpoint->port, bound_endpoint.port);
    ASSERT_STR_EQUALS(endpoint->address, bound_endpoint.address);

    if (options->type == AWS_SOCKET_STREAM) {
        ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
        ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming, &listener_args));
    }

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, options));
    if (local && (strcmp(local->address, endpoint->address) != 0 || local->port != endpoint->port)) {
        ASSERT_SUCCESS(aws_socket_bind(&outgoing, local));
    }
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    if (listener.options.type == AWS_SOCKET_STREAM) {
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

    if (options->type == AWS_SOCKET_STREAM) {
        ASSERT_TRUE(listener_args.incoming_invoked);
        ASSERT_FALSE(listener_args.error_invoked);
        server_sock = listener_args.incoming;
        ASSERT_TRUE(outgoing_args.connect_invoked);
        ASSERT_FALSE(outgoing_args.error_invoked);
        ASSERT_INT_EQUALS(options->domain, listener_args.incoming->options.domain);
        ASSERT_INT_EQUALS(options->type, listener_args.incoming->options.type);
    }

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
        aws_event_loop_schedule_task_now(event_loop, &close_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

        aws_socket_clean_up(listener_args.incoming);
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&outgoing);

    io_args.socket = &listener;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&listener);

    aws_event_loop_destroy(event_loop);

    return 0;
}

static int s_test_socket(
    struct aws_allocator *allocator,
    struct aws_socket_options *options,
    struct aws_socket_endpoint *endpoint) {

    return s_test_socket_ex(allocator, options, NULL, endpoint);
}

static int s_test_local_socket_communication(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;
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

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
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
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    aws_mutex_unlock(&mutex);
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_TIMEOUT, outgoing_args.last_error);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(connect_timeout, s_test_connect_timeout)

static int s_test_connect_timeout_cancelation(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);
    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
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
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    aws_event_loop_group_release(el_group);

    aws_thread_join_all_managed();

    ASSERT_INT_EQUALS(AWS_IO_EVENT_LOOP_SHUTDOWN, outgoing_args.last_error);
    aws_socket_clean_up(&outgoing);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(connect_timeout_cancelation, s_test_connect_timeout_cancelation)

struct error_test_args {
    int error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
};

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

static int s_test_outgoing_local_sock_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

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
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    ASSERT_FAILS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_null_sock_connection, &args));
    ASSERT_TRUE(
        aws_last_error() == AWS_IO_SOCKET_CONNECTION_REFUSED || aws_last_error() == AWS_ERROR_FILE_INVALID_PATH);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(outgoing_local_sock_errors, s_test_outgoing_local_sock_errors)

static bool s_outgoing_tcp_error_predicate(void *args) {
    struct error_test_args *test_args = (struct error_test_args *)args;

    return test_args->error_code != 0;
}

static int s_test_outgoing_tcp_sock_error(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 50000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {
        .address = "127.0.0.1",
        .port = 8567,
    };

    struct error_test_args args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    /* tcp connect is non-blocking, it should return success, but the error callback will be invoked. */
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_null_sock_connection, &args));
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, s_outgoing_tcp_error_predicate, &args));
    ASSERT_SUCCESS(aws_mutex_unlock(&args.mutex));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CONNECTION_REFUSED, args.error_code);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(outgoing_tcp_sock_error, s_test_outgoing_tcp_sock_error)

static int s_test_incoming_tcp_sock_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    if (!s_test_running_as_root(allocator)) {
        struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

        ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
        ASSERT_SUCCESS(aws_event_loop_run(event_loop));

        struct aws_socket_options options;
        AWS_ZERO_STRUCT(options);
        options.connect_timeout_ms = 1000;
        options.type = AWS_SOCKET_STREAM;
        options.domain = AWS_SOCKET_IPV4;

        struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = 80,
        };

        struct aws_socket incoming;
        ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options));
        ASSERT_ERROR(AWS_ERROR_NO_PERMISSION, aws_socket_bind(&incoming, &endpoint));

        aws_socket_clean_up(&incoming);
        aws_event_loop_destroy(event_loop);
    }
    return 0;
}

AWS_TEST_CASE(incoming_tcp_sock_errors, s_test_incoming_tcp_sock_errors)

static int s_test_incoming_duplicate_tcp_bind_errors(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

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
    ASSERT_SUCCESS(aws_socket_bind(&incoming, &endpoint));
    ASSERT_SUCCESS(aws_socket_listen(&incoming, 1024));
    struct aws_socket duplicate_bind;
    ASSERT_SUCCESS(aws_socket_init(&duplicate_bind, allocator, &options));
    ASSERT_ERROR(AWS_IO_SOCKET_ADDRESS_IN_USE, aws_socket_bind(&duplicate_bind, &endpoint));

    aws_socket_close(&duplicate_bind);
    aws_socket_clean_up(&duplicate_bind);
    aws_socket_close(&incoming);
    aws_socket_clean_up(&incoming);
    aws_event_loop_destroy(event_loop);
    return 0;
}

AWS_TEST_CASE(incoming_duplicate_tcp_bind_errors, s_test_incoming_duplicate_tcp_bind_errors)

/* Ensure that binding to port 0 results in OS assigning a port */
static int s_test_bind_on_zero_port(
    struct aws_allocator *allocator,
    enum aws_socket_type sock_type,
    enum aws_socket_domain sock_domain,
    const char *address) {

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

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

    ASSERT_SUCCESS(aws_socket_bind(&incoming, &endpoint));

    ASSERT_SUCCESS(aws_socket_get_bound_address(&incoming, &local_address1));

    if (sock_type != AWS_SOCKET_DGRAM) {
        ASSERT_SUCCESS(aws_socket_listen(&incoming, 1024));
    }

    ASSERT_TRUE(local_address1.port > 0);
    ASSERT_STR_EQUALS(address, local_address1.address);

    /* ensure that querying again gets the same results */
    struct aws_socket_endpoint local_address2;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&incoming, &local_address2));
    ASSERT_INT_EQUALS(local_address1.port, local_address2.port);
    ASSERT_STR_EQUALS(local_address1.address, local_address2.address);

    aws_socket_close(&incoming);
    aws_socket_clean_up(&incoming);
    aws_event_loop_destroy(event_loop);
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

        struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

        ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
        ASSERT_SUCCESS(aws_event_loop_run(event_loop));

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
        ASSERT_FAILS(aws_socket_bind(&incoming, &endpoint));
        int error = aws_last_error();
        ASSERT_TRUE(AWS_IO_SOCKET_INVALID_ADDRESS == error || AWS_ERROR_NO_PERMISSION == error);

        aws_socket_clean_up(&incoming);
        aws_event_loop_destroy(event_loop);
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
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

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
    aws_socket_bind(&socket, &endpoint);
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
    aws_event_loop_destroy(event_loop);

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

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
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
    };

    struct aws_socket outgoing;

    struct aws_task destroy_task = {
        .fn = s_test_destroy_socket_task,
        .arg = &outgoing,
    };

    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));
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
    aws_socket_clean_up(socket);
    aws_condition_variable_notify_one(listener_args->condition_variable);
    aws_mutex_unlock(listener_args->mutex);
}

static int s_cleanup_in_accept_doesnt_explode(struct aws_allocator *allocator, void *ctx) {
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
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8129};

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options));

    ASSERT_SUCCESS(aws_socket_bind(&listener, &endpoint));

    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    ASSERT_SUCCESS(
        aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming_destroy_listener, &listener_args));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

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
    };

    struct aws_task close_task = {
        .fn = s_socket_close_task,
        .arg = &io_args,
    };

    if (listener_args.incoming) {
        io_args.socket = listener_args.incoming;
        io_args.close_completed = false;
        aws_event_loop_schedule_task_now(event_loop, &close_task);
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
        ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

        aws_socket_clean_up(listener_args.incoming);
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}
AWS_TEST_CASE(cleanup_in_accept_doesnt_explode, s_cleanup_in_accept_doesnt_explode)

static void s_on_written_destroy(struct aws_socket *socket, int error_code, size_t amount_written, void *user_data) {
    (void)socket;
    struct socket_io_args *write_args = user_data;
    aws_mutex_lock(write_args->mutex);
    write_args->error_code = error_code;
    write_args->amount_written = amount_written;
    aws_socket_clean_up(socket);
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
    options.keepalive = true;
    options.keep_alive_interval_sec = 1000;
    options.keep_alive_timeout_sec = 60000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8130};

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options));

    ASSERT_SUCCESS(aws_socket_bind(&listener, &endpoint));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming, &listener_args));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

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
    };

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
    aws_event_loop_schedule_task_now(event_loop, &write_task);
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    aws_mem_release(allocator, server_sock);
    aws_socket_clean_up(&listener);
    aws_event_loop_destroy(event_loop);

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

static struct {
    struct aws_allocator *allocator;
    struct aws_event_loop *event_loop;
    struct aws_socket *write_socket;
    struct aws_socket *read_socket;
    bool currently_writing;
    enum async_role next_expected_callback;

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
            if (AWS_IO_READ_WOULD_BLOCK == aws_last_error()) {
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

/**
 * aws_socket_write()'s completion callback MUST fire asynchronously.
 * Otherwise, we can get multiple write() calls in the same callstack, which
 * leads to esoteric bugs (https://github.com/aws/aws-iot-device-sdk-cpp-v2/issues/194).
 */
static int s_sock_write_cb_is_async(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* set up server (read) and client (write) sockets */
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

    ASSERT_SUCCESS(aws_socket_bind(&listener, &endpoint));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming, &listener_args));

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

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

    /* cleanup */
    aws_socket_clean_up(&listener);
    aws_event_loop_destroy(event_loop);
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

    ASSERT_SUCCESS(aws_socket_bind(&listener, &endpoint));

    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));

    /* do the connect after the named pipe has been created (in the bind call), but before the connect named pipe call
       has been made in start accept. This will ensure IOCP does what we think it does. */
    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));

    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming, &listener_args));
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

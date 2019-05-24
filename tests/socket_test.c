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

#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

#if _MSC_VER
#    pragma warning(disable : 4996) /* sprintf */
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
    AWS_UNUSED_PARAM(socket);
    struct local_listener_args *listener_args = (struct local_listener_args *)user_data;
    aws_mutex_lock(listener_args->mutex);

    if (!error_code) {
        listener_args->incoming = new_socket;
        listener_args->incoming_invoked = true;
    } else {
        listener_args->error_invoked = true;
    }
    aws_condition_variable_notify_one(listener_args->condition_variable);
    aws_mutex_unlock(listener_args->mutex);
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
    AWS_UNUSED_PARAM(socket);
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)user_data;

    aws_mutex_lock(outgoing_args->mutex);

    if (!error_code) {
        outgoing_args->connect_invoked = true;

    } else {
        outgoing_args->last_error = error_code;
        outgoing_args->error_invoked = true;
    }

    aws_condition_variable_notify_one(outgoing_args->condition_variable);
    aws_mutex_unlock(outgoing_args->mutex);
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
    AWS_UNUSED_PARAM(socket);
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
    AWS_UNUSED_PARAM(task);
    AWS_UNUSED_PARAM(status);

    struct socket_io_args *io_args = args;
    aws_socket_write(io_args->socket, io_args->to_write, s_on_written, io_args);
}

static void s_read_task(struct aws_task *task, void *args, enum aws_task_status status) {
    AWS_UNUSED_PARAM(task);
    AWS_UNUSED_PARAM(status);

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

    aws_condition_variable_notify_one(&io_args->condition_variable);
    aws_mutex_unlock(io_args->mutex);
}

static void s_on_readable(struct aws_socket *socket, int error_code, void *user_data) {
    AWS_UNUSED_PARAM(socket);
    AWS_UNUSED_PARAM(user_data);
    AWS_UNUSED_PARAM(error_code);
}

static bool s_close_completed_predicate(void *arg) {
    struct socket_io_args *io_args = (struct socket_io_args *)arg;

    return io_args->close_completed;
}

static void s_socket_close_task(struct aws_task *task, void *args, enum aws_task_status status) {
    AWS_UNUSED_PARAM(task);
    AWS_UNUSED_PARAM(status);
    struct socket_io_args *io_args = args;
    aws_mutex_lock(io_args->mutex);
    aws_socket_close(io_args->socket);
    io_args->close_completed = true;
    aws_condition_variable_notify_one(&io_args->condition_variable);
    aws_mutex_unlock(io_args->mutex);
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
    AWS_ASSERT(!err);

    err = aws_socket_bind(&socket, &endpoint);
    err |= aws_socket_listen(&socket, 1024);
    bool is_root = !err;
    aws_socket_clean_up(&socket);
    return is_root;
}

static int s_test_socket(
    struct aws_allocator *allocator,
    struct aws_socket_options *options,
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

    if (options->type == AWS_SOCKET_STREAM) {
        ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
        ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming, &listener_args));
    }

    struct local_outgoing_args outgoing_args = {
        .mutex = &mutex, .condition_variable = &condition_variable, .connect_invoked = false, .error_invoked = false};

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    if (listener.options.type == AWS_SOCKET_STREAM) {
        ASSERT_SUCCESS(
            aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    }
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));

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
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    io_args.socket = server_sock;
    struct aws_task read_task = {
        .fn = s_read_task,
        .arg = &io_args,
    };

    aws_event_loop_schedule_task_now(event_loop, &read_task);
    aws_condition_variable_wait(&io_args.condition_variable, &mutex);
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);
    ASSERT_BIN_ARRAYS_EQUALS(read_buffer.buffer, read_buffer.len, write_buffer.buffer, write_buffer.len);

    if (options->type != AWS_SOCKET_DGRAM) {
        memset((void *)write_data, 0, sizeof(write_data));
        write_buffer.len = 0;

        io_args.error_code = 0;
        io_args.amount_written = 0;
        io_args.socket = server_sock;
        aws_event_loop_schedule_task_now(event_loop, &write_task);
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
        ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

        io_args.socket = &outgoing;
        aws_event_loop_schedule_task_now(event_loop, &read_task);
        aws_condition_variable_wait(&io_args.condition_variable, &mutex);
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
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

        aws_socket_clean_up(listener_args.incoming);
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

    aws_socket_clean_up(&outgoing);

    io_args.socket = &listener;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

    aws_socket_clean_up(&listener);

    aws_event_loop_destroy(event_loop);

    return 0;
}

static int s_test_local_socket_communication(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));
    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.address, sizeof(endpoint.address), LOCAL_SOCK_TEST_PATTERN, (long long unsigned)timestamp);

    return s_test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(local_socket_communication, s_test_local_socket_communication)

static int s_test_tcp_socket_communication(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

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

static int s_test_udp_socket_communication(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 8126};

    return s_test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(udp_socket_communication, s_test_udp_socket_communication)

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

static void s_test_host_resolved_test_callback(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {

    AWS_UNUSED_PARAM(resolver);
    AWS_UNUSED_PARAM(host_name);
    AWS_UNUSED_PARAM(err_code);

    struct test_host_callback_data *callback_data = user_data;

    aws_mutex_lock(callback_data->mutex);
    struct aws_host_address *host_address = NULL;

    if (aws_array_list_length(host_addresses) == 1) {
        aws_array_list_get_at_ptr(host_addresses, (void **)&host_address, 0);

        aws_host_address_copy(host_address, &callback_data->a_address);
        callback_data->has_a_address = true;
    }

    callback_data->invoked = true;
    aws_condition_variable_notify_one(&callback_data->condition_variable);
    aws_mutex_unlock(callback_data->mutex);
}

static int s_test_connect_timeout(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 1));
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(&el_group);
    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_host_resolver resolver;
    ASSERT_SUCCESS(aws_host_resolver_init_default(&resolver, allocator, 2, &el_group));

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
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        &resolver, host_name, s_test_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_test_host_resolved_predicate, &host_callback_data);

    aws_host_resolver_clean_up(&resolver);

    ASSERT_TRUE(host_callback_data.has_a_address);

    struct aws_socket_endpoint endpoint = {.port = 81};
    sprintf(endpoint.address, "%s", aws_string_bytes(host_callback_data.a_address.address));

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
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_TIMEOUT, outgoing_args.last_error);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_group_clean_up(&el_group);

    return 0;
}

AWS_TEST_CASE(connect_timeout, s_test_connect_timeout)

struct error_test_args {
    int error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
};

static void s_null_sock_connection(struct aws_socket *socket, int error_code, void *user_data) {
    AWS_UNUSED_PARAM(socket);
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
    AWS_UNUSED_PARAM(ctx);

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
    ASSERT_TRUE(aws_last_error() == AWS_IO_SOCKET_CONNECTION_REFUSED || aws_last_error() == AWS_IO_FILE_INVALID_PATH);

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
    AWS_UNUSED_PARAM(ctx);
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
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_null_sock_connection, &args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, s_outgoing_tcp_error_predicate, &args));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CONNECTION_REFUSED, args.error_code);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(outgoing_tcp_sock_error, s_test_outgoing_tcp_sock_error)

static int s_test_incoming_tcp_sock_errors(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);
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
        ASSERT_ERROR(AWS_IO_NO_PERMISSION, aws_socket_bind(&incoming, &endpoint));

        aws_socket_clean_up(&incoming);
        aws_event_loop_destroy(event_loop);
    }
    return 0;
}

AWS_TEST_CASE(incoming_tcp_sock_errors, s_test_incoming_tcp_sock_errors)

static int s_test_incoming_udp_sock_errors(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);
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
        ASSERT_TRUE(AWS_IO_SOCKET_INVALID_ADDRESS == error || AWS_IO_NO_PERMISSION == error);

        aws_socket_clean_up(&incoming);
        aws_event_loop_destroy(event_loop);
    }
    return 0;
}

AWS_TEST_CASE(incoming_udp_sock_errors, s_test_incoming_udp_sock_errors)

static void s_on_null_readable_notification(struct aws_socket *socket, int error_code, void *user_data) {
    AWS_UNUSED_PARAM(socket);
    AWS_UNUSED_PARAM(error_code);
    AWS_UNUSED_PARAM(user_data);
}

static int s_test_wrong_thread_read_write_fails(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);
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

    aws_mutex_lock(&mutex);
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

    aws_socket_clean_up(&socket);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(wrong_thread_read_write_fails, s_test_wrong_thread_read_write_fails)

static void s_test_destroy_socket_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    AWS_UNUSED_PARAM(task);
    AWS_UNUSED_PARAM(status);

    struct aws_socket *socket = arg;
    aws_socket_clean_up(socket);
}

static int s_cleanup_before_connect_or_timeout_doesnt_explode(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 1));
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(&el_group);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_host_resolver resolver;
    ASSERT_SUCCESS(aws_host_resolver_init_default(&resolver, allocator, 2, &el_group));

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
    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        &resolver, host_name, s_test_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_test_host_resolved_predicate, &host_callback_data);

    aws_host_resolver_clean_up(&resolver);

    ASSERT_TRUE(host_callback_data.has_a_address);

    struct aws_socket_endpoint endpoint = {.port = 81};
    sprintf(endpoint.address, "%s", aws_string_bytes(host_callback_data.a_address.address));

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
    ASSERT_ERROR(
        AWS_ERROR_COND_VARIABLE_TIMED_OUT,
        aws_condition_variable_wait_for(
            &condition_variable,
            &mutex,
            aws_timestamp_convert(options.connect_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL)));
    ASSERT_FALSE(outgoing_args.connect_invoked);
    ASSERT_FALSE(outgoing_args.error_invoked);

    aws_event_loop_group_clean_up(&el_group);

    return 0;
}

AWS_TEST_CASE(cleanup_before_connect_or_timeout_doesnt_explode, s_cleanup_before_connect_or_timeout_doesnt_explode)

static void s_local_listener_incoming_destroy_listener(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    AWS_UNUSED_PARAM(socket);
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
    AWS_UNUSED_PARAM(ctx);

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

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));

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
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

        aws_socket_clean_up(listener_args.incoming);
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}
AWS_TEST_CASE(cleanup_in_accept_doesnt_explode, s_cleanup_in_accept_doesnt_explode)

static void s_on_written_destroy(struct aws_socket *socket, int error_code, size_t amount_written, void *user_data) {
    AWS_UNUSED_PARAM(socket);
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
    AWS_UNUSED_PARAM(task);
    AWS_UNUSED_PARAM(status);

    struct socket_io_args *io_args = args;
    aws_socket_write(io_args->socket, io_args->to_write, s_on_written_destroy, io_args);
}

static int s_cleanup_in_write_cb_doesnt_explode(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

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

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));

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
    aws_condition_variable_wait_pred(
        &io_args.condition_variable, &mutex, s_write_completed_predicate_destroy, &io_args);
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    memset((void *)write_data, 0, sizeof(write_data));
    write_buffer.len = 0;

    io_args.error_code = 0;
    io_args.amount_written = 0;
    io_args.socket = server_sock;
    aws_event_loop_schedule_task_now(event_loop, &write_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_write_completed_predicate, &io_args);
    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, io_args.error_code);

    aws_mem_release(allocator, server_sock);
    aws_socket_clean_up(&listener);
    aws_event_loop_destroy(event_loop);

    return 0;
}
AWS_TEST_CASE(cleanup_in_write_cb_doesnt_explode, s_cleanup_in_write_cb_doesnt_explode)

#ifdef _WIN32
static int s_local_socket_pipe_connected_race(struct aws_allocator *allocator, void *ctx) {
    AWS_UNUSED_PARAM(ctx);

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

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));
    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.address, sizeof(endpoint.address), LOCAL_SOCK_TEST_PATTERN, (long long unsigned)timestamp);

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

    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint, event_loop, s_local_outgoing_connection, &outgoing_args));

    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, s_local_listener_incoming, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, s_incoming_predicate, &listener_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_connection_completed_predicate, &outgoing_args));

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
        aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

        aws_socket_clean_up(listener_args.incoming);
        aws_mem_release(allocator, listener_args.incoming);
    }

    io_args.socket = &outgoing;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

    aws_socket_clean_up(&outgoing);

    io_args.socket = &listener;
    io_args.close_completed = false;
    aws_event_loop_schedule_task_now(event_loop, &close_task);
    aws_condition_variable_wait_pred(&io_args.condition_variable, &mutex, s_close_completed_predicate, &io_args);

    aws_socket_clean_up(&listener);

    aws_event_loop_destroy(event_loop);

    return 0;
}
AWS_TEST_CASE(local_socket_pipe_connected_race, s_local_socket_pipe_connected_race)

#endif

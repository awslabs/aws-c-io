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
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>

struct local_listener_args {
    struct aws_socket *incoming;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    bool incoming_invoked;
    bool error_invoked;
};

static bool incoming_predicate(void *arg) {
    struct local_listener_args *listener_args = (struct local_listener_args *)arg;

    return listener_args->incoming_invoked || listener_args->error_invoked;
}

static void local_listener_incoming(struct aws_socket *socket, struct aws_socket *new_socket, void *ctx) {
    struct local_listener_args *listener_args = (struct local_listener_args *)ctx;
    listener_args->incoming = new_socket;
    listener_args->incoming_invoked = true;
    aws_condition_variable_notify_one(listener_args->condition_variable);
}

static void local_listener_error(struct aws_socket *socket, int err_code, void *ctx) {
    struct local_listener_args *listener_args = (struct local_listener_args *)ctx;
    listener_args->error_invoked = true;
}

struct local_outgoing_args {
    bool connect_invoked;
    bool error_invoked;
    int last_error;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
};

static bool connection_completed_predicate(void *arg) {
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)arg;

    return outgoing_args->connect_invoked || outgoing_args->error_invoked;
}

static void local_outgoing_connection(struct aws_socket *socket, void *ctx) {
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)ctx;

    aws_condition_variable_notify_one(outgoing_args->condition_variable);

    outgoing_args->connect_invoked = true;

    if (socket->options.domain != AWS_SOCKET_LOCAL) {
        aws_mutex_unlock(outgoing_args->mutex);
    }
}

static void local_outgoing_connection_error(struct aws_socket *socket, int err_code, void *ctx) {
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)ctx;
    outgoing_args->error_invoked = true;
}

static int test_socket (struct aws_allocator *allocator, struct aws_socket_options *options, struct aws_socket_endpoint *endpoint) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

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

    struct aws_socket_creation_args listener_creation_args = {
            .on_incoming_connection = local_listener_incoming,
            .on_error = local_listener_error,
            .on_connection_established = NULL,
            .ctx = &listener_args,
    };

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, options, event_loop, &listener_creation_args));

    ASSERT_SUCCESS(aws_socket_bind(&listener, endpoint));

    if(options->type != AWS_SOCKET_DGRAM) {
        ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
        ASSERT_SUCCESS(aws_socket_start_accept(&listener));
    }

    struct local_outgoing_args outgoing_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .connect_invoked = false,
            .error_invoked = false
    };

    struct aws_socket_creation_args outgoing_creation_args = {
            .on_connection_established = local_outgoing_connection,
            .on_error = local_outgoing_connection_error,
            .ctx = &outgoing_args
    };

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, options, event_loop, &outgoing_creation_args));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, endpoint));

    if (options->type == AWS_SOCKET_STREAM) {
        ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, incoming_predicate, &listener_args));
        ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, connection_completed_predicate, &outgoing_args));
    }

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

    /* now test the read and write across the connection. */
    const char read_data[] = "I'm a little teapot";
    const char write_data[sizeof(read_data)] = {0};

    struct aws_byte_buf read_buffer = aws_byte_buf_from_array((const uint8_t *)read_data, sizeof(read_data));
    struct aws_byte_buf write_buffer = aws_byte_buf_from_array((const uint8_t *)write_data, sizeof(write_data));

    size_t data_len = 0;
    ASSERT_SUCCESS(aws_socket_write(&outgoing, &read_buffer, &data_len));
    ASSERT_INT_EQUALS(read_buffer.len, data_len);
    ASSERT_SUCCESS(aws_socket_read(server_sock, &write_buffer, &data_len));
    ASSERT_INT_EQUALS(read_buffer.len, data_len);

    ASSERT_BIN_ARRAYS_EQUALS(read_buffer.buffer, read_buffer.len, write_buffer.buffer, write_buffer.len);

    memset((void *)write_data, 0, sizeof(write_data));

    if (options->type == AWS_SOCKET_STREAM) {
        ASSERT_SUCCESS(aws_socket_write(server_sock, &read_buffer, &data_len));
        ASSERT_INT_EQUALS(read_buffer.len, data_len);
        ASSERT_SUCCESS(aws_socket_read(&outgoing, &write_buffer, &data_len));
        ASSERT_INT_EQUALS(read_buffer.len, data_len);

        ASSERT_BIN_ARRAYS_EQUALS(read_buffer.buffer, read_buffer.len, write_buffer.buffer, write_buffer.len);
    }

    aws_socket_clean_up(server_sock);

    if (listener_args.incoming) {
        aws_mem_release(allocator, listener_args.incoming);
    }

    aws_socket_clean_up(&outgoing);
    aws_socket_clean_up(&listener);
    aws_event_loop_destroy(event_loop);

    return 0;
}

static int test_local_socket_communication (struct aws_allocator *allocator, void *ctx) {
    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));
    struct aws_socket_endpoint endpoint;

    sprintf(endpoint.socket_name, "testsock%llu.sock", (long long unsigned)timestamp);

    return test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(local_socket_communication, test_local_socket_communication)

static int test_tcp_socket_communication (struct aws_allocator *allocator, void *ctx) {
    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = "8125"
    };

    return test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(tcp_socket_communication, test_tcp_socket_communication)

static int test_udp_socket_communication (struct aws_allocator *allocator, void *ctx) {
    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = "8126"
    };

    return test_socket(allocator, &options, &endpoint);
}

AWS_TEST_CASE(udp_socket_communication, test_udp_socket_communication)


static void timeout_error_handler(struct aws_socket *socket, int err_code, void *ctx) {
    struct local_outgoing_args *outgoing_args = (struct local_outgoing_args *)ctx;

    outgoing_args->error_invoked = true;
    outgoing_args->last_error = err_code;
    aws_condition_variable_notify_one(outgoing_args->condition_variable);
    aws_mutex_unlock(outgoing_args->mutex);
}

static int test_connect_timeout (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .address = "216.58.217.46",
            .port = "81"
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_outgoing_args outgoing_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .connect_invoked = false,
            .error_invoked = false
    };

    struct aws_socket_creation_args outgoing_creation_args = {
            .on_connection_established = local_outgoing_connection,
            .on_error = timeout_error_handler,
            .ctx = &outgoing_args
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options, event_loop, &outgoing_creation_args));
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint));
    ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &mutex));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_TIMEOUT, outgoing_args.last_error);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(connect_timeout, test_connect_timeout)

struct error_test_args {
    int error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
};

static void null_sock_error_handler(struct aws_socket *socket, int err_code, void *ctx) {
    struct error_test_args *error_args = (struct error_test_args *)ctx;

    error_args->error_code = err_code;
    aws_condition_variable_notify_one(&error_args->condition_variable);
}

static void null_sock_connection(struct aws_socket *socket, void *ctx) {
}

static int test_outgoing_local_sock_errors (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .socket_name = ""
    };

    struct error_test_args args = {
         .error_code = 0,
         .mutex = AWS_MUTEX_INIT,
         .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_socket_creation_args outgoing_creation_args = {
            .on_connection_established = null_sock_connection,
            .on_error = null_sock_error_handler,
            .ctx = &args
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options, event_loop, &outgoing_creation_args));
    ASSERT_ERROR(AWS_IO_SOCKET_CONNECTION_REFUSED, aws_socket_connect(&outgoing, &endpoint));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CONNECTION_REFUSED, args.error_code);

    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(outgoing_local_sock_errors, test_outgoing_local_sock_errors)

static int test_incoming_local_sock_errors (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .socket_name = "/usr/blah"
    };

    struct error_test_args args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_socket_creation_args incoming_creation_args = {
            .on_connection_established = null_sock_connection,
            .on_error = null_sock_error_handler,
            .ctx = &args
    };

    struct aws_socket incoming;
    ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options, event_loop, &incoming_creation_args));
    ASSERT_ERROR(AWS_IO_NO_PERMISSION, aws_socket_bind(&incoming, &endpoint));

    aws_socket_clean_up(&incoming);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(incoming_local_sock_errors, test_incoming_local_sock_errors)

static bool outgoing_tcp_error_predicate(void *args) {
    struct error_test_args *test_args = (struct error_test_args *)args;

    return test_args->error_code != 0;
}

static int test_outgoing_tcp_sock_error (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 50000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = "8567"
    };

    struct error_test_args args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_socket_creation_args outgoing_creation_args = {
            .on_connection_established = null_sock_connection,
            .on_error = null_sock_error_handler,
            .ctx = &args
    };

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options, event_loop, &outgoing_creation_args));
    /* tcp connect is non-blocking, it should return success, but the error callback will be invoked. */
    ASSERT_SUCCESS(aws_mutex_lock(&args.mutex));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, outgoing_tcp_error_predicate, &args));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CONNECTION_REFUSED, args.error_code);


    aws_socket_clean_up(&outgoing);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(outgoing_tcp_sock_error, test_outgoing_tcp_sock_error)

static int test_incoming_tcp_sock_errors (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 1000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = "80"
    };

    struct error_test_args args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_socket_creation_args incoming_creation_args = {
            .on_connection_established = null_sock_connection,
            .on_error = null_sock_error_handler,
            .ctx = &args
    };

    struct aws_socket incoming;
    ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options, event_loop, &incoming_creation_args));
    ASSERT_ERROR(AWS_IO_NO_PERMISSION, aws_socket_bind(&incoming, &endpoint));

    aws_socket_clean_up(&incoming);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(incoming_tcp_sock_errors, test_incoming_tcp_sock_errors)

static int test_incoming_udp_sock_errors (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 1000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = "80"
    };

    struct error_test_args args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_socket_creation_args incoming_creation_args = {
            .on_connection_established = null_sock_connection,
            .on_error = null_sock_error_handler,
            .ctx = &args
    };

    struct aws_socket incoming;
    ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options, event_loop, &incoming_creation_args));
    ASSERT_ERROR(AWS_IO_NO_PERMISSION, aws_socket_bind(&incoming, &endpoint));

    aws_socket_clean_up(&incoming);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(incoming_udp_sock_errors, test_incoming_udp_sock_errors)

static int test_non_connected_read_write_fails (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 1000;
    options.type = AWS_SOCKET_DGRAM;
    options.domain = AWS_SOCKET_IPV4;

    /* hit a endpoint that will not send me a SYN packet. */
    struct aws_socket_endpoint endpoint = {
            .address = "127.0.0.1",
            .port = "80"
    };

    struct error_test_args args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_socket_creation_args incoming_creation_args = {
            .on_connection_established = null_sock_connection,
            .on_error = null_sock_error_handler,
            .ctx = &args
    };

    struct aws_socket incoming;
    ASSERT_SUCCESS(aws_socket_init(&incoming, allocator, &options, event_loop, &incoming_creation_args));
    ASSERT_ERROR(AWS_IO_NO_PERMISSION, aws_socket_bind(&incoming, &endpoint));
    ASSERT_ERROR(AWS_IO_SOCKET_NOT_CONNECTED, aws_socket_read(&incoming, NULL, NULL));
    ASSERT_ERROR(AWS_IO_SOCKET_NOT_CONNECTED, aws_socket_write(&incoming, NULL, NULL));

    aws_socket_clean_up(&incoming);
    aws_event_loop_destroy(event_loop);

    return 0;
}

AWS_TEST_CASE(non_connected_read_write_fails, test_non_connected_read_write_fails)

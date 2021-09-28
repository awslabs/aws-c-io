/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * See PKCS11.md for instructions on running these tests
 */

#include <aws/io/pkcs11.h>
#include <aws/io/private/pkcs11_private.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_LIB, "TEST_PKCS11_LIB");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_TOKEN_LABEL, "TEST_PKCS11_TOKEN_LABEL");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_PIN, "TEST_PKCS11_PIN");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_PKEY_LABEL, "TEST_PKCS11_PKEY_LABEL");

/* Singleton that stores env-var values */
struct pkcs11_tester {
    struct aws_string *filepath;
    struct aws_string *token_label;
    struct aws_string *pin;
    struct aws_string *pkey_label;
};
static struct pkcs11_tester s_pkcs11_tester;

static void s_pkcs11_tester_clean_up(void) {
    aws_string_destroy(s_pkcs11_tester.filepath);
    aws_string_destroy(s_pkcs11_tester.token_label);
    aws_string_destroy(s_pkcs11_tester.pin);
    aws_string_destroy(s_pkcs11_tester.pkey_label);
    aws_io_library_clean_up();
}

/* Read env-vars.
 * Raise an error if any necessary ones are missing */
static int s_pkcs11_tester_init(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    const struct aws_string *env_var = TEST_PKCS11_LIB;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.filepath);
    if (s_pkcs11_tester.filepath == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_TOKEN_LABEL;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.token_label);
    if (s_pkcs11_tester.token_label == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_PIN;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.pin);
    if (s_pkcs11_tester.pin == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_PKEY_LABEL;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.pkey_label);
    if (s_pkcs11_tester.pkey_label == NULL) {
        goto missing;
    }

    return AWS_OP_SUCCESS;

missing:
    printf("Missing required env-var '%s'\n", aws_string_c_str(env_var));
    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

/* Simplest test: Loads and unloads library, calling C_Initialize() and C_Finalize() */
static int s_test_pkcs11_lib_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Clean up */
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_initialize, s_test_pkcs11_lib_initialize)

/* Test that we can use the `omit_initialize` option to have the library loaded multiple times */
static int s_test_pkcs11_lib_omit_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    struct aws_pkcs11_lib_options options_normal = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };

    struct aws_pkcs11_lib_options options_omit_initialize = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
        .omit_initialize = true,
    };

    /* First test that we fail gracefully if we omit_initialize, but no one else has initialized it yet either */
    struct aws_pkcs11_lib *pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_IO_PKCS11_ERROR, aws_last_error());

    /* Next test that we can load the library twice by using omit_initialize the second time we load it */
    struct aws_pkcs11_lib *pkcs11_lib_1 = aws_pkcs11_lib_new(allocator, &options_normal);
    ASSERT_NOT_NULL(pkcs11_lib_1);

    struct aws_pkcs11_lib *pkcs11_lib_2 = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NOT_NULL(pkcs11_lib_2);

    /* Next test that omit_initialize is required if someone else already initialized the library */
    pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_normal);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_IO_PKCS11_ERROR, aws_last_error());

    /* Clean up */
    aws_pkcs11_lib_release(pkcs11_lib_2);
    aws_pkcs11_lib_release(pkcs11_lib_1);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_omit_initialize, s_test_pkcs11_lib_omit_initialize)

static int s_test_pkcs11_find_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Find token slot*/
    CK_SLOT_ID slot_id;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, s_pkcs11_tester.token_label, &slot_id /*out*/));

    /* Open session */
    CK_SESSION_HANDLE session_handle;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, slot_id, &session_handle /*out*/));

    /* Login user */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_handle, s_pkcs11_tester.pin));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle;
    CK_KEY_TYPE pkey_type;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        pkcs11_lib, session_handle, s_pkcs11_tester.pkey_label, &pkey_handle, &pkey_type));
    ASSERT_TRUE(CK_INVALID_HANDLE != pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_pkcs11_lib_close_session(pkcs11_lib, session_handle);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key, s_test_pkcs11_find_private_key)

struct tls_tester {
    struct {
        struct aws_mutex mutex;
        struct aws_condition_variable cvar;

        bool server_results_ready;
        int server_error_code;

        bool client_results_ready;
        int client_error_code;
    } synced;
};
static struct tls_tester s_tls_tester;

static bool s_are_client_results_ready(void *user_data) {
    (void)user_data;
    return s_tls_tester.synced.client_results_ready;
}

static bool s_are_server_results_ready(void *user_data) {
    (void)user_data;
    return s_tls_tester.synced.client_results_ready;
}

/* callback when client TLS connection established (or failed) */
static void s_on_tls_client_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS client setup. error_code=%s", aws_error_name(error_code));

    /* if negotiation succeds: shutdown channel nicely
     * if negotiation fails: store error code and notify main thread */
    if (error_code == 0) {
        aws_channel_shutdown(channel, 0);
    } else {
        aws_mutex_lock(&s_tls_tester.synced.mutex);
        s_tls_tester.synced.client_error_code = error_code;
        s_tls_tester.synced.client_results_ready = true;
        aws_mutex_unlock(&s_tls_tester.synced.mutex);
        aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
    }
}

/* callback when client TLS connection finishes shutdown (doesn't fire if setup failed) */
static void s_on_tls_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS client shutdown. error_code=%s", aws_error_name(error_code));

    /* store error code and notify main thread  */
    aws_mutex_lock(&s_tls_tester.synced.mutex);
    s_tls_tester.synced.client_error_code = error_code;
    s_tls_tester.synced.client_results_ready = true;
    aws_mutex_unlock(&s_tls_tester.synced.mutex);
    aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
}

/* callback when server TLS connection established (or failed) */
static void s_on_tls_server_channel_setup(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS server setup. error_code=%s", aws_error_name(error_code));

    if (error_code == 0) {
        /* do nothing, the client will shut down this channel */
        return;
    } else {
        /* store error code and notify main thread  */
        aws_mutex_lock(&s_tls_tester.synced.mutex);
        s_tls_tester.synced.server_error_code = error_code;
        s_tls_tester.synced.server_results_ready = true;
        aws_mutex_unlock(&s_tls_tester.synced.mutex);
        aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
    }
}

/* callback when server TLS connection established (or failed) */
static void s_on_tls_server_channel_shutdown(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS server shutdown. error_code=%s", aws_error_name(error_code));

    /* store error code and notify main thread  */
    aws_mutex_lock(&s_tls_tester.synced.mutex);
    s_tls_tester.synced.server_error_code = error_code;
    s_tls_tester.synced.server_results_ready = true;
    aws_mutex_unlock(&s_tls_tester.synced.mutex);
    aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
}

/* Connect a client client and server, where the client is using PKCS#11 for private key operations */
static int s_test_pkcs11_tls_negotiation_succeeds(struct aws_allocator *allocator, void *ctx) {
    /* Set up resources that aren't specific to server or client */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    struct aws_pkcs11_lib_options pkcs11_lib_opts = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.filepath),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &pkcs11_lib_opts);
    ASSERT_NOT_NULL(pkcs11_lib);

    ASSERT_SUCCESS(aws_mutex_init(&s_tls_tester.synced.mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&s_tls_tester.synced.cvar));

    struct aws_event_loop_group *event_loop_group =
        aws_event_loop_group_new_default(allocator, 1, NULL /*shutdown_opts*/);
    ASSERT_NOT_NULL(event_loop_group);

    struct aws_host_resolver_default_options resolver_opts = {
        .el_group = event_loop_group,
    };
    struct aws_host_resolver *host_resolver = aws_host_resolver_new_default(allocator, &resolver_opts);
    ASSERT_NOT_NULL(host_resolver);

    /* use randomly named local domain socket */
    struct aws_socket_endpoint endpoint = {.address = {0}, .port = 0};
    {
        struct aws_byte_buf addr_buf = aws_byte_buf_from_empty_array(endpoint.address, sizeof(endpoint.address));
        ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&addr_buf, aws_byte_cursor_from_c_str("testsock-")));

        struct aws_uuid addr_uuid;
        ASSERT_SUCCESS(aws_uuid_init(&addr_uuid));
        ASSERT_SUCCESS(aws_uuid_to_str(&addr_uuid, &addr_buf));

        ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&addr_buf, aws_byte_cursor_from_c_str(".sock")));
    }

    struct aws_socket_options sock_opts = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_LOCAL,
        .connect_timeout_ms = 3000,
    };

    /* Set up a server that does mutual TLS. The server will not use PKCS#11 */

    struct aws_tls_ctx_options server_tls_opts;
    ASSERT_SUCCESS(aws_tls_ctx_options_init_default_server_from_path(
        &server_tls_opts, allocator, "unittests.crt", "unittests.key"));

    /* trust the client's self-signed certificate */
    ASSERT_SUCCESS(aws_tls_ctx_options_override_default_trust_store_from_path(
        &server_tls_opts, NULL /*ca_path*/, "unittests.crt"));

    aws_tls_ctx_options_set_verify_peer(&server_tls_opts, true);

    struct aws_tls_ctx *server_tls_ctx = aws_tls_server_ctx_new(allocator, &server_tls_opts);
    ASSERT_NOT_NULL(server_tls_ctx);
    aws_tls_ctx_options_clean_up(&server_tls_opts);

    struct aws_tls_connection_options server_tls_connection_opts;
    aws_tls_connection_options_init_from_ctx(&server_tls_connection_opts, server_tls_ctx);

    struct aws_server_bootstrap *server_bootstrap = aws_server_bootstrap_new(allocator, event_loop_group);
    ASSERT_NOT_NULL(server_bootstrap);

    struct aws_server_socket_channel_bootstrap_options server_listener_sock_opts = {
        .bootstrap = server_bootstrap,
        .host_name = endpoint.address,
        .port = endpoint.port,
        .socket_options = &sock_opts,
        .tls_options = &server_tls_connection_opts,
        .incoming_callback = s_on_tls_server_channel_setup,
        .shutdown_callback = s_on_tls_server_channel_shutdown,
    };

    struct aws_socket *server_listener_sock = aws_server_bootstrap_new_socket_listener(&server_listener_sock_opts);
    ASSERT_NOT_NULL(server_listener_sock);

    /* Set up a client that does mutual TLS, using PKCS#11 for private key operations */

    struct aws_tls_ctx_pkcs11_options client_pkcs11_tls_opts = {
        .pkcs11_lib = pkcs11_lib,
        .token_label = aws_byte_cursor_from_string(s_pkcs11_tester.token_label),
        .user_pin = aws_byte_cursor_from_string(s_pkcs11_tester.pin),
        .private_key_object_label = aws_byte_cursor_from_string(s_pkcs11_tester.pkey_label),
        .cert_file_path = aws_byte_cursor_from_c_str("unittests.crt"),
    };
    struct aws_tls_ctx_options client_tls_opts;
    ASSERT_SUCCESS(
        aws_tls_ctx_options_init_client_mtls_with_pkcs11(&client_tls_opts, allocator, &client_pkcs11_tls_opts));

    /* trust the server's self-signed certificate */
    ASSERT_SUCCESS(aws_tls_ctx_options_override_default_trust_store_from_path(
        &client_tls_opts, NULL /*ca_path*/, "unittests.crt"));

    struct aws_tls_ctx *client_tls_ctx = aws_tls_client_ctx_new(allocator, &client_tls_opts);
    ASSERT_NOT_NULL(client_tls_ctx);
    aws_tls_ctx_options_clean_up(&client_tls_opts);

    struct aws_client_bootstrap_options client_bootstrap_opts = {
        .event_loop_group = event_loop_group,
        .host_resolver = host_resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_opts);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("localhost");
    struct aws_tls_connection_options client_tls_connection_opts;
    aws_tls_connection_options_init_from_ctx(&client_tls_connection_opts, client_tls_ctx);
    ASSERT_SUCCESS(aws_tls_connection_options_set_server_name(&client_tls_connection_opts, allocator, &server_name));
    struct aws_socket_channel_bootstrap_options client_channel_opts = {
        .bootstrap = client_bootstrap,
        .host_name = endpoint.address,
        .port = endpoint.port,
        .socket_options = &sock_opts,
        .tls_options = &client_tls_connection_opts,
        .setup_callback = s_on_tls_client_channel_setup,
        .shutdown_callback = s_on_tls_client_channel_shutdown,
    };

    /* finally, tell the client to connect */
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_opts));

    /* Wait for connection to go through */

    /* CRITICAL SECTION */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&s_tls_tester.synced.mutex));

        /* wait for client to successfully create connection and tear it down */
        ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
            &s_tls_tester.synced.cvar,
            &s_tls_tester.synced.mutex,
            (int64_t)AWS_TIMESTAMP_NANOS * 10 /*10sec timeout*/,
            s_are_client_results_ready,
            NULL /*user_data*/));
        ASSERT_INT_EQUALS(0, s_tls_tester.synced.client_error_code);

        /* ensure the server also had a good experience */
        ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
            &s_tls_tester.synced.cvar,
            &s_tls_tester.synced.mutex,
            (int64_t)AWS_TIMESTAMP_NANOS * 10 /*10sec timeout*/,
            s_are_server_results_ready,
            NULL /*user_data*/));
        ASSERT_INT_EQUALS(0, s_tls_tester.synced.server_error_code);

        ASSERT_SUCCESS(aws_mutex_unlock(&s_tls_tester.synced.mutex));
    }
    /* CRITICAL SECTION */

    /* clean up */
    aws_tls_ctx_release(client_tls_ctx);
    aws_client_bootstrap_release(client_bootstrap);
    aws_tls_connection_options_clean_up(&client_tls_connection_opts);

    aws_server_bootstrap_destroy_socket_listener(server_bootstrap, server_listener_sock);
    aws_tls_connection_options_clean_up(&server_tls_connection_opts);
    aws_server_bootstrap_release(server_bootstrap);
    aws_tls_ctx_release(server_tls_ctx);
    aws_host_resolver_release(host_resolver);
    aws_event_loop_group_release(event_loop_group);

    ASSERT_SUCCESS(aws_thread_join_all_managed());

    aws_condition_variable_clean_up(&s_tls_tester.synced.cvar);
    aws_mutex_clean_up(&s_tls_tester.synced.mutex);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_init(allocator);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_tls_negotiation_succeeds, s_test_pkcs11_tls_negotiation_succeeds)

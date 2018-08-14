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

#if _MSC_VER
#    pragma warning(disable : 4100) /* unreferenced formal parameter */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#    pragma warning(disable : 4221) /* initialization using address of automatic variable */
#endif

#include <pipe_test.c>

#include <event_loop_test.c>
#include <socket_test.c>
#include <channel_test.c>
#include <socket_handler_test.c>
#include <tls_handler_test.c>
#include <alpn_handler_test.c>
#include <default_host_resolver_test.c>

#if AWS_USE_IO_COMPLETION_PORTS
#    define EVENT_LOOP_IO_TESTS &event_loop_completion_events
#else
#    define EVENT_LOOP_IO_TESTS &read_write_notifications
#endif

static int s_run_tests(int argc, char *argv[]) {
    AWS_RUN_TEST_CASES(
            &pipe_open_close,
            &pipe_read_write,
            &pipe_read_write_large_buffer,
            &xthread_scheduled_tasks_execute,
            EVENT_LOOP_IO_TESTS,
            &stop_then_restart,
            &channel_setup,
            &channel_single_slot_cleans_up,
            &channel_slots_clean_up,
            &channel_message_passing,
            &event_loop_group_setup_and_shutdown,
            &event_loop_group_counter_overflow,
            &local_socket_communication,
            &tcp_socket_communication,
            &udp_socket_communication,
            &connect_timeout,
            &outgoing_local_sock_errors,
            &incoming_local_sock_errors,
            &outgoing_tcp_sock_error,
            &incoming_tcp_sock_errors,
            &incoming_udp_sock_errors,
            &non_connected_read_write_fails,
            &test_default_with_ipv6_lookup,
            &test_default_with_ipv4_only_lookup,
            &test_default_with_multiple_lookups,
            &test_resolver_ttls,
            &test_resolver_connect_failure_recording,
            &test_resolver_ttl_refreshes_on_resolve,
            &socket_handler_echo_and_backpressure,
            &socket_handler_close,
            &tls_channel_echo_and_backpressure_test,
            /*&tls_channel_negotiation_error,*/
            &alpn_successfully_negotiates,
            &alpn_no_protocol_message,
            &alpn_error_creating_handler);
}

int main(int argc, char *argv[]) {
    aws_io_load_error_strings();
    aws_tls_init_static_state(aws_default_allocator());
    int ret_val = s_run_tests(argc, argv);
    aws_tls_clean_up_static_state(aws_default_allocator());
    return ret_val;
}

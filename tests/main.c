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

#include <read_write_test_handler.c>

#include <channel_test.c>

#include <mock_dns_resolver.c>

#include <default_host_resolver_test.c>

#include <file_utils_test.c>

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
        &test_default_with_ipv6_lookup,
        &test_default_with_ipv4_only_lookup,
        &test_default_with_multiple_lookups,
        &test_resolver_ttls,
        &test_resolver_connect_failure_recording,
        &test_resolver_ttl_refreshes_on_resolve,
        &test_pem_single_cert_parse );
}

int main(int argc, char *argv[]) {
    int ret_val = s_run_tests(argc, argv);
    return ret_val;
}

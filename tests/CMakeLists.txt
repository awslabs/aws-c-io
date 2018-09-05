include(AwsTestHarness)
enable_testing()

file(GLOB TEST_SRC "*.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(pipe_open_close)
add_test_case(pipe_read_write)
add_test_case(pipe_read_write_large_buffer)
add_test_case(xthread_scheduled_tasks_execute)
if (USE_IO_COMPLETION_PORTS)
    add_test_case(event_loop_completion_events)
else ()
    add_test_case(read_write_notifications)
endif ()
add_test_case(stop_then_restart)
add_test_case(event_loop_group_setup_and_shutdown)
add_test_case(event_loop_group_counter_overflow)

add_test_case(channel_setup)
add_test_case(channel_single_slot_cleans_up)
add_test_case(channel_slots_clean_up)
#DISABLED DUE TO HANG ON WINDOWS add_test_case(channel_message_passing)
#DISABLED DUE TO FAILURE ON WINDOWS add_test_case(test_default_with_ipv6_lookup)
add_test_case(test_default_with_ipv4_only_lookup)
#DISABLED DUE TO FAILURE ON WINDOWS add_test_case(test_default_with_multiple_lookups)
add_test_case(test_resolver_ttls)
add_test_case(test_resolver_connect_failure_recording)
add_test_case(test_resolver_ttl_refreshes_on_resolve)

add_test_case(test_pem_single_cert_parse)
add_test_case(test_pem_private_key_parse)
add_test_case(test_pem_cert_chain_parse)
add_test_case(test_pem_cert_parse_from_file)
add_test_case(test_pem_private_key_parse_from_file)
add_test_case(test_pem_cert_chain_comments_and_whitespace)
add_test_case(test_pem_invalid_parse)
add_test_case(test_pem_valid_data_invalid_parse)
add_test_case(test_pem_invalid_in_chain_parse)

set(TEST_BINARY_NAME ${CMAKE_PROJECT_NAME}-tests)
generate_test_driver(${TEST_BINARY_NAME})

#SSL certificates to use for testing.
add_custom_command(TARGET ${TEST_BINARY_NAME} PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/resources ${CMAKE_CURRENT_BINARY_DIR})



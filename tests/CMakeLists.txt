include(CTest)
enable_testing()

file(GLOB TEST_SRC "main.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

set(TEST_BINARY_NAME ${CMAKE_PROJECT_NAME}-tests)

add_executable(${TEST_BINARY_NAME} ${TESTS})
target_link_libraries(${TEST_BINARY_NAME} ${CMAKE_PROJECT_NAME})
set_target_properties(${TEST_BINARY_NAME} PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_compile_definitions(${TEST_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
if (MSVC)
    target_compile_options(${TEST_BINARY_NAME} PRIVATE /W4 /WX)
else ()
    target_compile_options(${TEST_BINARY_NAME} PRIVATE -Wall -Wno-long-long -Werror)
endif ()

#SSL certificates to use for testing.
add_custom_command(TARGET ${TEST_BINARY_NAME} PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/resources ${CMAKE_CURRENT_BINARY_DIR})

add_test(pipe_open_close ${TEST_BINARY_NAME} pipe_open_close)
add_test(pipe_read_write ${TEST_BINARY_NAME} pipe_read_write)
add_test(pipe_read_write_large_buffer ${TEST_BINARY_NAME} pipe_read_write_large_buffer)
add_test(xthread_scheduled_tasks_execute ${TEST_BINARY_NAME} xthread_scheduled_tasks_execute)
if (USE_IO_COMPLETION_PORTS)
    add_test(event_loop_completion_events, ${TEST_BINARY_NAME} event_loop_completion_events)
else ()
    add_test(read_write_notifications ${TEST_BINARY_NAME} read_write_notifications)
endif ()

add_test(stop_then_restart ${TEST_BINARY_NAME} stop_then_restart)
add_test(event_loop_group_setup_and_shutdown ${TEST_BINARY_NAME} event_loop_group_setup_and_shutdown)
add_test(event_loop_group_counter_overflow ${TEST_BINARY_NAME} event_loop_group_counter_overflow)

add_test(local_socket_communication ${TEST_BINARY_NAME} local_socket_communication)
add_test(tcp_socket_communication ${TEST_BINARY_NAME} tcp_socket_communication)
add_test(udp_socket_communication ${TEST_BINARY_NAME} udp_socket_communication)
add_test(connect_timeout ${TEST_BINARY_NAME} connect_timeout)
add_test(outgoing_local_sock_errors ${TEST_BINARY_NAME} outgoing_local_sock_errors)
add_test(incoming_local_sock_errors ${TEST_BINARY_NAME} incoming_local_sock_errors)
add_test(outgoing_tcp_sock_error ${TEST_BINARY_NAME} outgoing_tcp_sock_error)
add_test(incoming_tcp_sock_errors ${TEST_BINARY_NAME} incoming_tcp_sock_errors)
add_test(incoming_udp_sock_errors ${TEST_BINARY_NAME} incoming_udp_sock_errors)
add_test(non_connected_read_write_fails ${TEST_BINARY_NAME} non_connected_read_write_fails)

add_test(channel_setup ${TEST_BINARY_NAME} channel_setup)
add_test(channel_single_slot_cleans_up ${TEST_BINARY_NAME} channel_single_slot_cleans_up)
add_test(channel_slots_clean_up ${TEST_BINARY_NAME} channel_slots_clean_up)
add_test(channel_message_passing ${TEST_BINARY_NAME} channel_message_passing)

add_test(socket_handler_echo_and_backpressure ${TEST_BINARY_NAME} socket_handler_echo_and_backpressure)
add_test(socket_handler_close ${TEST_BINARY_NAME} socket_handler_close)

add_test(tls_channel_echo_and_backpressure_test ${TEST_BINARY_NAME} tls_channel_echo_and_backpressure_test)
#add_test(tls_channel_negotiation_error ${TEST_BINARY_NAME} tls_channel_negotiation_error)

add_test(alpn_successfully_negotiates ${TEST_BINARY_NAME} alpn_successfully_negotiates)
add_test(alpn_no_protocol_message ${TEST_BINARY_NAME} alpn_no_protocol_message)
add_test(alpn_error_creating_handler ${TEST_BINARY_NAME} alpn_error_creating_handler)

add_test(test_default_with_ipv6_lookup ${TEST_BINARY_NAME} test_default_with_ipv6_lookup)
add_test(test_default_with_ipv4_only_lookup ${TEST_BINARY_NAME} test_default_with_ipv4_only_lookup)
add_test(test_default_with_multiple_lookups ${TEST_BINARY_NAME} test_default_with_multiple_lookups)
add_test(test_resolver_ttls ${TEST_BINARY_NAME} test_resolver_ttls)
add_test(test_resolver_connect_failure_recording ${TEST_BINARY_NAME} test_resolver_connect_failure_recording)
add_test(test_resolver_ttl_refreshes_on_resolve ${TEST_BINARY_NAME} test_resolver_ttl_refreshes_on_resolve)

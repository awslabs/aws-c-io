include(AwsTestHarness)
enable_testing()

# See PKCS11.md for instructions on running these tests
option(ENABLE_PKCS11_TESTS "Build and run PKCS#11 tests" OFF)

file(GLOB TEST_SRC "*.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

# Each pipe test runs in 2 different configurations
macro(add_pipe_test_case name)
    add_test_case("${name}")
    add_test_case("${name}_2loops")
endmacro()

add_test_case(io_library_init)
add_test_case(io_library_init_cleanup_init_cleanup)
add_test_case(io_library_error_order)

# Dispatch Queue does not support pipe
if(NOT AWS_USE_APPLE_NETWORK_FRAMEWORK)
add_pipe_test_case(pipe_open_close)
add_pipe_test_case(pipe_read_write)
add_pipe_test_case(pipe_read_write_large_buffer)
add_pipe_test_case(pipe_readable_event_sent_after_write)
add_pipe_test_case(pipe_readable_event_sent_once)
add_pipe_test_case(pipe_readable_event_sent_on_subscribe_if_data_present)
add_pipe_test_case(pipe_readable_event_sent_on_resubscribe_if_data_present)
add_pipe_test_case(pipe_readable_event_sent_again_after_all_data_read)
add_pipe_test_case(pipe_error_event_sent_after_write_end_closed)
add_pipe_test_case(pipe_error_event_sent_on_subscribe_if_write_end_already_closed)
add_pipe_test_case(pipe_writes_are_fifo)
add_pipe_test_case(pipe_clean_up_cancels_pending_writes)
endif()


add_test_case(event_loop_xthread_scheduled_tasks_execute)
add_test_case(event_loop_canceled_tasks_run_in_el_thread)

if(USE_IO_COMPLETION_PORTS)
    add_test_case(event_loop_completion_events)
elseif(NOT AWS_USE_APPLE_NETWORK_FRAMEWORK) # Dispatch Queue does not support pipe
    add_test_case(event_loop_subscribe_unsubscribe)
    add_test_case(event_loop_writable_event_on_subscribe)
    add_test_case(event_loop_no_readable_event_before_write)
    add_test_case(event_loop_readable_event_after_write)
    add_test_case(event_loop_readable_event_on_subscribe_if_data_present)
    add_test_case(event_loop_readable_event_on_2nd_time_readable)
    add_test_case(event_loop_no_events_after_unsubscribe)
endif()

add_test_case(event_loop_stop_then_restart)
add_test_case(event_loop_multiple_stops)
add_test_case(event_loop_group_setup_and_shutdown)
add_test_case(event_loop_group_setup_and_shutdown_async)
add_test_case(numa_aware_event_loop_group_setup_and_shutdown)
add_test_case(event_loop_epoll_creation)
add_test_case(event_loop_iocp_creation)
add_test_case(event_loop_kqueue_creation)
add_test_case(event_loop_dispatch_queue_creation)

add_test_case(io_testing_channel)

add_test_case(socket_posix_creation)
add_test_case(socket_winsock_creation)
add_test_case(local_socket_communication)
add_net_test_case(tcp_socket_communication)
add_net_test_case(udp_socket_communication)
add_net_test_case(test_socket_with_bind_to_interface)
add_net_test_case(test_socket_with_bind_to_invalid_interface)
add_net_test_case(test_is_network_interface_name_valid)
add_net_test_case(connect_timeout)


if(USE_VSOCK)
    add_test_case(vsock_loopback_socket_communication)
endif()

add_test_case(outgoing_local_sock_errors)
add_test_case(outgoing_tcp_sock_error)
add_test_case(incoming_tcp_sock_errors)
add_net_test_case(bind_on_zero_port_tcp_ipv4)
add_net_test_case(bind_on_zero_port_udp_ipv4)
add_test_case(incoming_udp_sock_errors)

add_test_case(cleanup_in_accept_doesnt_explode)
add_test_case(cleanup_in_write_cb_doesnt_explode)
add_test_case(sock_write_cb_is_async)
add_test_case(socket_validate_port)

add_test_case(parse_ipv4_valid_addresses)
add_test_case(parse_ipv4_invalid_addresses)
add_test_case(parse_ipv6_valid_addresses)
add_test_case(parse_ipv6_invalid_addresses)

if(NOT AWS_USE_APPLE_NETWORK_FRAMEWORK)
# Apple Network Framework does not support bind+connect
add_test_case(udp_bind_connect_communication)
# The read/write will always run a different thread for Apple Network Framework
add_test_case(wrong_thread_read_write_fails)
# Apple Network Framework would not validate the binding endpoint until we start the
# listen. The test does not apply here.
add_test_case(incoming_duplicate_tcp_bind_errors)
# nw_socket does not allow clean up event loop before socket shutdown, thus the following tests triggered
# by event loop shutdown would not apply to Apple Network Framework
add_net_test_case(connect_timeout_cancelation)
add_net_test_case(cleanup_before_connect_or_timeout_doesnt_explode)
endif()

if(WIN32)
    string(REPLACE "." ";" BUILD_VERSION ${CMAKE_HOST_SYSTEM_VERSION})
    list(GET BUILD_VERSION 2 BUILD_V)
    message("Windows Version " ${CMAKE_HOST_SYSTEM_VERSION} ", build " ${BUILD_V})

    if(${BUILD_V} GREATER_EQUAL 20348)
        message("Building for version 20348 or higher: supporting TLS1.3")
        add_net_test_case(tls_client_channel_negotiation_success_mtls_tls1_3)
    endif()
    add_test_case(local_socket_pipe_connected_race)
    add_test_case(tls_client_channel_negotiation_success_ecc384_deprecated)
endif()

add_test_case(channel_setup)
add_test_case(channel_single_slot_cleans_up)
add_test_case(channel_slots_clean_up)
add_test_case(channel_refcount_delays_clean_up)
add_test_case(channel_tasks_run)
add_test_case(channel_tasks_serialized_run)
add_test_case(channel_rejects_post_shutdown_tasks)
add_test_case(channel_cancels_pending_tasks)
add_test_case(channel_duplicate_shutdown)
add_test_case(channel_keeps_event_loop_group_alive)
add_net_test_case(channel_connect_some_hosts_timeout)

add_net_test_case(test_default_with_ipv6_lookup)
add_net_test_case(test_default_host_resolver_ipv6_address_variations)
add_test_case(test_resolver_ipv6_address_lookup)
add_net_test_case(test_default_with_multiple_lookups)
add_test_case(test_resolver_ipv4_address_lookup)
add_test_case(test_resolver_purge_host_cache)
add_test_case(test_resolver_purge_cache)
add_net_test_case(test_default_with_ipv4_only_lookup)
add_test_case(test_resolver_ttls)
add_test_case(test_resolver_connect_failure_recording)
add_test_case(test_resolver_ttl_refreshes_on_resolve)
add_test_case(test_resolver_bad_list_expires_eventually)
add_test_case(test_resolver_low_frequency_starvation)

add_test_case(test_pem_single_cert_parse)
add_test_case(test_pem_private_key_parse)
add_test_case(test_pem_cert_chain_parse)
add_test_case(test_pem_cert_parse_from_file)
add_test_case(test_pem_cert_parse_from_file_crlf)
add_test_case(test_pem_private_key_parse_from_file)
add_test_case(test_pem_cert_chain_comments_and_whitespace)
add_test_case(test_pem_invalid_parse)
add_test_case(test_pem_valid_data_invalid_parse)
add_test_case(test_pem_invalid_in_chain_parse)

add_test_case(pem_sanitize_comments_around_pem_object_removed)
add_test_case(pem_sanitize_empty_file_rejected)
add_test_case(pem_sanitize_wrong_format_rejected)
add_test_case(pem_sanitize_bad_format_rejected)

add_test_case(socket_handler_echo_and_backpressure)
add_test_case(socket_handler_close)


# These tests fail on Windows due to some bug in our server code where, if the socket is closed
# immediately after data is written, that data does not flush cleanly to the client.
# I've lost days to this bug, and no one is using our Windows server funcionality,
# so disabling these tests on Windows and moving along for now.
# I tried the following:
# 1) Wrote 2 simple standalone Windows programs, server and client, using simple synchronous socket code.
#    WORKED PERFECTLY. So it's not a fundamental issue with Windows.
# 2) Commented out server part of this failing test, and used the simple standalone server instead.
#    WORKED PERFECTLY. So it's not a problem with our actual client code.
# 3) Copy/pasted the simple standlone server code into this test, and used that instead of our actual server code.
#    WORKED PERFECTLY. So it's not a problem with the server and client sockets being in the same process.
# 4) Commented out the client part of this failing test, and used the simple standalone client instead.
#    FAILED. The standalone client got WSAECONNRESET (Connection reset by peer) before receiving all the data.
#    So it's something with our complicated non-blocking server code.
#    The last interesting thing I noticed before giving up was: we call shutdown() immediately
#    before calling closesocket() but shutdown() gets error WSAENOTCONN, even
#    though, at that moment, the socket should be connected just fine.
if(NOT WIN32)
    add_net_test_case(socket_handler_read_to_eof_after_peer_hangup)
    add_net_test_case(socket_handler_ipv4_read_to_eof_after_peer_hangup)
    add_net_test_case(socket_handler_ipv6_read_to_eof_after_peer_hangup)
endif()
add_test_case(socket_pinned_event_loop)
add_net_test_case(socket_pinned_event_loop_dns_failure)

if(NOT BYO_CRYPTO)
    if(USE_S2N)
        add_net_test_case(default_pki_path_exists)
    endif()

    # Badssl-based tests (https://badssl.com/dashboard/) - use remote endpoints for now, later transition to
    # internal hosting using the bad ssl container/server setup and dns redirects per
    # https://github.com/chromium/badssl.com
    #
    # We don't use the interception suite since that's a host configuration issue
    # We also don't check the domain security policy suite:
    # 1. s2n does not support revocation checks and we do not currently enable any revocation checks
    # in windows or osx, although we may add configurable support to those platforms(off-by-default) at a
    # later date
    # 2. s2n does not support public key pinning and, given its deprecated and http-centric position, there are no
    # plans to add support nor investigate osx/windows support as well.

    # Badssl - Certificate Validation endpoint suite
    # For each failure case, we also include a positive test that verifies success when peer verification is disabled
    add_net_test_case(tls_client_channel_negotiation_error_expired)
    add_net_test_case(tls_client_channel_negotiation_error_wrong_host)
    add_net_test_case(tls_client_channel_negotiation_error_wrong_host_with_ca_override)
    add_net_test_case(tls_client_channel_negotiation_error_self_signed)
    add_net_test_case(tls_client_channel_negotiation_error_untrusted_root)
    add_net_test_case(tls_client_channel_negotiation_error_untrusted_root_due_to_ca_override)
    add_net_test_case(tls_client_channel_negotiation_no_verify_expired)
    add_net_test_case(tls_client_channel_negotiation_no_verify_wrong_host)
    add_net_test_case(tls_client_channel_negotiation_no_verify_self_signed)
    add_net_test_case(tls_client_channel_negotiation_no_verify_untrusted_root)

    # Badssl - Broken Crypto endpoint suite
    # We don't include dh1024 as it succeeds on the windows baseline configuration and there does not seem
    # to be a way to disable it
    add_net_test_case(tls_client_channel_negotiation_error_broken_crypto_rc4)
    add_net_test_case(tls_client_channel_negotiation_error_broken_crypto_rc4_md5)
    add_net_test_case(tls_client_channel_negotiation_error_broken_crypto_dh480)
    add_net_test_case(tls_client_channel_negotiation_error_broken_crypto_dh512)
    add_net_test_case(tls_client_channel_negotiation_error_broken_crypto_null)

    # Badssl - Legacy crypto suite, includes both negative and positive tests, with override checks where appropriate
    # Our current baseline/default is platform-specific, whereas badssl expects a baseline of 1.2
    # Linux - tls1.1
    # Windows - system default (1.0 is the only thing we could reasonable fixate to given win7 support)
    # Mac - system default
    # We skip the cbc and 3des checks, as a positive connection result there does not yet represent a security risk
    # We don't include dh2048 as it succeeds on the windows baseline configuration and there does not seem
    # to be a way to disable it
    if(NOT(WIN32 AND NOT CMAKE_SYSTEM_VERSION MATCHES "10\.0\.1.*"))
        # Skip TLS 1.0 and TLS 1.1 test for windows later than windows server 2022, as they droped old TLS
        if(NOT AWS_USE_SECITEM)
        add_net_test_case(tls_client_channel_negotiation_error_legacy_crypto_tls10)
        # SecItem does not allow use of depricated TLS versions
        add_net_test_case(tls_client_channel_negotiation_override_legacy_crypto_tls10)
        add_net_test_case(tls_client_channel_negotiation_success_legacy_crypto_tls11)
        endif()
        add_net_test_case(tls_client_channel_negotiation_error_override_legacy_crypto_tls11)
    endif()

    # Badssl - Secure uncommon suite
    # We skip 10000san for now as its unclear the point or relevance especially with respect to the OS-based
    # TLS implementations
    # We skip 1000san, sha384, rsa8192 and sha512 because the public badssl certificate is expired and we haven't migrated to
    # internal hosting yet
    # We also defer the incomplete chain test for now until we can do some further study on how to get it to
    # properly fail on windows and osx.
    # add_net_test_case(tls_client_channel_negotiation_success_sha384)
    # add_net_test_case(tls_client_channel_negotiation_success_sha512)
    # add_net_test_case(tls_client_channel_negotiation_success_rsa8192)
    add_net_test_case(tls_client_channel_negotiation_error_no_subject)
    add_net_test_case(tls_client_channel_negotiation_success_no_verify_no_subject)
    add_net_test_case(tls_client_channel_negotiation_error_no_common_name)
    add_net_test_case(tls_client_channel_negotiation_success_no_verify_no_common_name)
    add_net_test_case(tls_client_channel_negotiation_success_no_verify_incomplete_chain)

    # Badssl - Secure common suite, all of these should succeed
    add_net_test_case(tls_client_channel_negotiation_success_tls12)
    add_net_test_case(tls_client_channel_negotiation_success_sha256)
    add_net_test_case(tls_client_channel_negotiation_success_rsa2048)
    add_net_test_case(tls_client_channel_negotiation_success_ecc256)
    add_net_test_case(tls_client_channel_negotiation_success_ecc384)

    # add_net_test_case(tls_client_channel_negotiation_success_extended_validation) test disabled until badssl updates cert (expired 2022.08.10)
    add_net_test_case(tls_client_channel_negotiation_success_mozilla_modern)

    # Misc non-badssl tls tests
    add_net_test_case(test_duplicate_cert_import)
    add_net_test_case(tls_channel_echo_and_backpressure_test)
    add_net_test_case(tls_channel_shutdown_with_cache_test)
    add_net_test_case(tls_channel_shutdown_with_cache_window_update_after_shutdown_test)
    add_net_test_case(tls_client_channel_negotiation_success)
    add_net_test_case(tls_server_multiple_connections)
    add_net_test_case(tls_server_hangup_during_negotiation)
    add_net_test_case(tls_client_channel_no_verify)
    add_net_test_case(test_tls_negotiation_timeout)
    add_net_test_case(alpn_successfully_negotiates)
    add_net_test_case(alpn_no_protocol_message)
    add_net_test_case(test_ecc_cert_import)
if(NOT AWS_USE_SECITEM)
    # These tests require the test binary to be codesigned with an Apple Developer account with entitlements.
    # The entitlements also require a provisioning profile and require the binary to be run from within XCode or a
    # valid app bundle.
    add_net_test_case(test_concurrent_cert_import)

    # PKCS8 is not supported on iOS. We will not support PKCS8 on macOS using SecItem.
    # PKCS8 support for SecItem can be added in the future but it will require macOS
    # specific branching of logic and import of the key into the keychain.
    add_net_test_case(test_pkcs8_import)

    # This test shuts down the channel after a socket is established but while the TLS handshake is taking place
    # further up the channel. Apple Network Framework's connection handles both the socket connection as well
    # as the TLS handshake within the same create connection call without external notification that the socket
    # has succeeded prior to the TLS negotiation. As such, this test will not work for Secitem.
    add_net_test_case(tls_client_channel_negotiation_error_socket_closed)

    # TLS statistics tracks and handles the timeout of TLS. Using SecItem, the TLS handshake takes place within
    # the socket establishment and does not need a separate timeout task for TLS.
    add_net_test_case(tls_channel_statistics_test)
endif()

    add_test_case(alpn_error_creating_handler)
    add_test_case(tls_destroy_null_context)
    add_net_test_case(tls_certificate_chain_test)

else()
    add_test_case(byo_tls_handler_test)
endif()

add_test_case(future_by_value)
add_test_case(future_void)
add_test_case(future_callback_fires_immediately)
add_test_case(future_callback_fires_on_another_thread)
add_test_case(future_register_callback_if_not_done)
add_test_case(future_register_event_loop_callback_after_done)
add_test_case(future_register_event_loop_callback_before_done)
add_test_case(future_register_event_loop_callback_always_scheduled)
add_test_case(future_register_channel_callback)
add_test_case(future_wait_timeout)
add_test_case(future_wait_timeout_max)
add_test_case(future_pointer_with_destroy)
add_test_case(future_pointer_with_release)
add_test_case(future_get_result_by_move)
add_test_case(future_can_die_incomplete)
add_test_case(future_by_pointer_accepts_null_result)
add_test_case(future_set_multiple_times)
add_test_case(future_set_error)

add_test_case(test_input_stream_memory_simple)
add_test_case(test_input_stream_memory_iterate)
add_test_case(test_input_stream_memory_seek_beginning)
add_test_case(test_input_stream_memory_seek_end)
add_test_case(test_input_stream_memory_seek_multiple_times)
add_test_case(test_input_stream_memory_seek_past_end)
add_test_case(test_input_stream_memory_seek_before_start)
add_test_case(test_input_stream_file_simple)
add_test_case(test_input_stream_file_iterate)
add_test_case(test_input_stream_file_seek_beginning)
add_test_case(test_input_stream_file_seek_end)
add_test_case(test_input_stream_memory_length)
add_test_case(test_input_stream_file_length)
add_test_case(test_input_stream_binary)
add_test_case(test_input_stream_read_only)

add_test_case(async_input_stream_fill_completes_on_thread)
add_test_case(async_input_stream_fill_completes_immediately)
add_test_case(async_input_stream_fill_completes_randomly)
add_test_case(async_input_stream_fill_eof_requires_extra_read)
add_test_case(async_input_stream_fill_reports_error)

add_test_case(open_channel_statistics_test)

add_test_case(shared_library_open_failure)

if(BUILD_SHARED_LIBS)
    add_test_case(shared_library_open_success)
    add_test_case(shared_library_find_function_failure)
    add_test_case(shared_library_find_function_success)
endif()

add_test_case(test_exponential_backoff_retry_too_many_retries_no_jitter)
add_test_case(test_exponential_backoff_retry_too_many_retries_full_jitter)
add_test_case(test_exponential_backoff_retry_too_many_retries_decorrelated_jitter)
add_test_case(test_exponential_backoff_retry_too_many_retries_default_jitter)
add_test_case(test_exponential_backoff_retry_client_errors_do_not_count)
add_test_case(test_exponential_backoff_retry_no_jitter_time_taken)
add_test_case(test_exponential_max_backoff_retry_no_jitter)
add_test_case(test_exponential_backoff_retry_invalid_options)
add_test_case(test_no_retries)

add_test_case(test_standard_retry_strategy_setup_shutdown)
add_test_case(test_standard_retry_strategy_failure_exhausts_bucket)
add_test_case(test_standard_retry_strategy_failure_recovers)

# See PKCS11.md for instructions on running these tests
if(ENABLE_PKCS11_TESTS)
    add_test_case(pkcs11_lib_sanity_check)
    add_test_case(pkcs11_lib_behavior_default)
    add_test_case(pkcs11_lib_behavior_omit_initialize)
    add_test_case(pkcs11_lib_behavior_strict_initialize_finalize)
    add_test_case(pkcs11_find_private_key)
    add_test_case(pkcs11_find_private_key_for_different_rsa_types)
    add_test_case(pkcs11_find_private_key_for_ec)
    add_test_case(pkcs11_find_multiple_private_key)
    add_test_case(pkcs11_sign_rsa_sha1)
    add_test_case(pkcs11_sign_rsa_sha224)
    add_test_case(pkcs11_sign_rsa_sha256)
    add_test_case(pkcs11_sign_rsa_sha384)
    add_test_case(pkcs11_sign_rsa_sha512)
    add_test_case(pkcs11_asn1_bigint)
    add_test_case(pkcs11_sign_ec_256)
    add_test_case(pkcs11_rsa_decrypt)
    add_test_case(pkcs11_find_slot)
    add_test_case(pkcs11_find_slot_many_tokens)
    add_test_case(pkcs11_session_tests)
    add_test_case(pkcs11_login_tests)

    # TLS with PKCS#11 not currently supported on every platform
    if(USE_S2N)
        add_test_case(pkcs11_tls_rsa_negotiation_succeeds)
        add_test_case(pkcs11_tls_ec_negotiation_succeeds)
    endif()
endif()

set(TEST_BINARY_NAME ${PROJECT_NAME}-tests)
generate_test_driver(${TEST_BINARY_NAME})

if(USE_S2N)
    target_compile_definitions(${PROJECT_NAME}-tests PRIVATE "-DUSE_S2N")
endif()

# SSL certificates to use for testing.
add_custom_command(TARGET ${TEST_BINARY_NAME} PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_SOURCE_DIR}/resources $<TARGET_FILE_DIR:${TEST_BINARY_NAME}>)

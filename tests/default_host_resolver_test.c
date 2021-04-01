/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/condition_variable.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>

#include <aws/common/clock.h>
#include <aws/io/event_loop.h>
#include <aws/io/host_resolver.h>
#include <aws/io/logging.h>

#include <aws/testing/aws_test_harness.h>

#include "mock_dns_resolver.h"

static const uint64_t FORCE_RESOLVE_SLEEP_TIME = 1500000000;

struct default_host_callback_data {
    struct aws_host_address aaaa_address;
    struct aws_host_address a_address;
    bool has_aaaa_address;
    bool has_a_address;
    struct aws_condition_variable condition_variable;
    bool invoked;
    struct aws_mutex *mutex;
    aws_thread_id_t callback_thread_id;
};

static bool s_default_host_resolved_predicate(void *arg) {
    struct default_host_callback_data *callback_data = arg;

    return callback_data->invoked;
}

static void s_default_host_resolved_test_callback(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {

    (void)resolver;
    (void)host_name;
    (void)err_code;

    struct default_host_callback_data *callback_data = user_data;

    aws_mutex_lock(callback_data->mutex);

    if (host_addresses != NULL) {
        struct aws_host_address *host_address = NULL;
        if (aws_array_list_length(host_addresses) >= 2) {
            aws_array_list_get_at_ptr(host_addresses, (void **)&host_address, 0);

            aws_host_address_copy(host_address, &callback_data->aaaa_address);

            aws_array_list_get_at_ptr(host_addresses, (void **)&host_address, 1);

            aws_host_address_copy(host_address, &callback_data->a_address);
            callback_data->has_aaaa_address = true;
            callback_data->has_a_address = true;
        } else if (aws_array_list_length(host_addresses) == 1) {
            aws_array_list_get_at_ptr(host_addresses, (void **)&host_address, 0);

            if (host_address->record_type == AWS_ADDRESS_RECORD_TYPE_A) {
                aws_host_address_copy(host_address, &callback_data->a_address);
                callback_data->has_a_address = true;
            } else if (host_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA) {
                aws_host_address_copy(host_address, &callback_data->aaaa_address);
                callback_data->has_aaaa_address = true;
            }
        }
    }

    callback_data->invoked = true;
    callback_data->callback_thread_id = aws_thread_current_thread_id();

    aws_mutex_unlock(callback_data->mutex);
    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static int s_test_default_with_ipv6_lookup_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "s3.dualstack.us-east-1.amazonaws.com");
    ASSERT_NOT_NULL(host_name);

    struct aws_host_resolution_config config = {
        .max_ttl = 10,
        .impl = aws_default_dns_resolve,
        .impl_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_TRUE(callback_data.has_aaaa_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_AAAA, callback_data.aaaa_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name),
        host_name->len,
        aws_string_bytes(callback_data.aaaa_address.host),
        callback_data.aaaa_address.host->len);
    ASSERT_TRUE(callback_data.has_a_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, callback_data.a_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name),
        host_name->len,
        aws_string_bytes(callback_data.a_address.host),
        callback_data.a_address.host->len);
    ASSERT_TRUE(callback_data.aaaa_address.address->len > 1);
    ASSERT_TRUE(callback_data.a_address.address->len > 1);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_string_destroy((void *)host_name);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_default_with_ipv6_lookup, s_test_default_with_ipv6_lookup_fn)

/* just FYI, this test assumes that "s3.us-east-1.amazonaws.com" does not return IPv6 addresses. */
static int s_test_default_with_ipv4_only_lookup_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "s3.us-east-1.amazonaws.com");
    ASSERT_NOT_NULL(host_name);

    struct aws_host_resolution_config config = {
        .max_ttl = 10,
        .impl = aws_default_dns_resolve,
        .impl_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_FALSE(callback_data.has_aaaa_address);
    ASSERT_TRUE(callback_data.has_a_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, callback_data.a_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name),
        host_name->len,
        aws_string_bytes(callback_data.a_address.host),
        callback_data.a_address.host->len);
    ASSERT_TRUE(callback_data.a_address.address->len > 1);
    aws_mutex_unlock(&mutex);

    aws_host_address_clean_up(&callback_data.a_address);
    aws_string_destroy((void *)host_name);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_default_with_ipv4_only_lookup, s_test_default_with_ipv4_only_lookup_fn)

/* there are multiple big assumptions in this test.
 * The first assumption is that s3.us-east-1.amazonaws.com will never return an IPv6 address.
 * The second assumption is that the TTLs for these records are one second and that the backend resolver
 * resolves at the TTL rate.
 * The third assumption is that this test runs in less than one second after the first background resolve.
 * The fourth assumption is that S3 does not return multiple addresses per A or AAAA record.
 * If any of these assumptions ever change, this test will likely be broken, but I don't know of a better way to test
 * this end-to-end. */
static int s_test_default_with_multiple_lookups_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name_1 = aws_string_new_from_c_str(allocator, "s3.dualstack.us-east-1.amazonaws.com");
    const struct aws_string *host_name_2 = aws_string_new_from_c_str(allocator, "s3.us-east-1.amazonaws.com");

    ASSERT_NOT_NULL(host_name_1);
    ASSERT_NOT_NULL(host_name_2);

    struct aws_host_resolution_config config = {
        .max_ttl = 10,
        .impl = aws_default_dns_resolve,
        .impl_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_1, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    struct aws_host_address host_1_original_ipv6_resolve;
    aws_host_address_copy(&callback_data.aaaa_address, &host_1_original_ipv6_resolve);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_2, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    struct aws_host_address host_2_original_ipv4_resolve;
    aws_host_address_copy(&callback_data.a_address, &host_2_original_ipv4_resolve);
    aws_host_address_clean_up(&callback_data.a_address);

    /* this will invoke in the calling thread since the address is already cached. */
    aws_mutex_unlock(&mutex);
    callback_data.invoked = false;
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_1, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_1_original_ipv6_resolve.address),
        host_1_original_ipv6_resolve.address->len,
        aws_string_bytes(callback_data.aaaa_address.address),
        callback_data.aaaa_address.address->len);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* this will invoke in the calling thread since the address is already cached. */
    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_2, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_2_original_ipv4_resolve.address),
        host_2_original_ipv4_resolve.address->len,
        aws_string_bytes(callback_data.a_address.address),
        callback_data.a_address.address->len);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_mutex_unlock(&mutex);

    aws_host_address_clean_up(&host_1_original_ipv6_resolve);
    aws_host_address_clean_up(&host_2_original_ipv4_resolve);

    aws_string_destroy((void *)host_name_1);
    aws_string_destroy((void *)host_name_2);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_default_with_multiple_lookups, s_test_default_with_multiple_lookups_fn)

static int s_test_resolver_ttls_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_new_from_c_str(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_new_from_c_str(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_new_from_c_str(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_new_from_c_str(allocator, "address2ipv6");

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_resolver, 2, allocator));

    struct aws_host_resolution_config config = {
        .max_ttl = 1,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver,
    };

    struct aws_host_address host_address_1_ipv4 = {
        .address = addr1_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_1_ipv6 = {
        .address = addr1_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_array_list address_list_1;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_1, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv4));
    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_resolver, &address_list_1));

    struct aws_host_address host_address_2_ipv4 = {
        .address = addr2_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv6 = {
        .address = addr2_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_array_list address_list_2;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_2, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_2, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_2, &host_address_2_ipv4));
    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_resolver, &address_list_2));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    /* sleep a bit more than one second, as a result the next resolve should run.*/
    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* sleep a bit more than one second, as a result the next resolve should run.*/
    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    /* note that normally, the first address would come back, but the TTL is expired (we set it to one second).
     * As a result, we should get the second one again.*/

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* sleep so entry two expires. Now everything is expired, but because the last thing we resolved was addr 2, it
     * should still be there. */
    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);
    aws_string_destroy((void *)host_name);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_ttls, s_test_resolver_ttls_fn)

static int s_test_resolver_connect_failure_recording_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_new_from_c_str(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_new_from_c_str(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_new_from_c_str(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_new_from_c_str(allocator, "address2ipv6");

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_resolver, 1000, allocator));

    struct aws_host_resolution_config config = {
        .max_ttl = 30,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver,
    };

    struct aws_host_address host_address_1_ipv4 = {
        .address = addr1_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_1_ipv6 = {
        .address = addr1_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv4 = {
        .address = addr2_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv6 = {
        .address = addr2_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_array_list address_list_1;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_1, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv4));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv4));

    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_resolver, &address_list_1));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    /* this should still be cached don't need the mutex here. */
    aws_mutex_unlock(&mutex);
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_1_ipv4));

    /* following the LRU policy, address 1 should be what gets returned here, however we marked it as failed, so it
     * should be skipped and address 2 should be returned. */
    aws_mutex_unlock(&mutex);
    callback_data.invoked = false;
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_2_ipv4));

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    /* here address 1 should be returned since it is now the least recently used address and all of them have failed..
     */
    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* let it re-resolve, and we should still have the other connections marked as connection failures. */
    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    /* here address 1 should still be the one returned because though we re-resolved, we don't trust the dns entries yet
     * and we kept them as bad addresses. */
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);
    aws_string_destroy((void *)host_name);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_connect_failure_recording, s_test_resolver_connect_failure_recording_fn)

static int s_test_resolver_ttl_refreshes_on_resolve_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_new_from_c_str(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_new_from_c_str(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_new_from_c_str(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_new_from_c_str(allocator, "address2ipv6");

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_resolver, 1000, allocator));

    struct aws_host_resolution_config config = {
        .max_ttl = 30,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver,
    };

    struct aws_host_address host_address_1_ipv4 = {
        .address = addr1_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_1_ipv6 = {
        .address = addr1_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv4 = {
        .address = addr2_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv6 = {
        .address = addr2_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_array_list address_list_1;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_1, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv4));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv4));

    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_resolver, &address_list_1));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));
    uint64_t address_1_expiry = callback_data.aaaa_address.expiry;

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    /* this will resolve in the calling thread, so don't take the lock. */
    aws_mutex_unlock(&mutex);
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));
    uint64_t address_2_expiry = callback_data.aaaa_address.expiry;

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    /* now we loop back around, we resolved, but the TTLs should not have expired at all (they were actually refreshed).
     */
    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    /* here address 1 should be returned since it is now the least recently used address.. */
    aws_mutex_lock(&mutex);

    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));
    ASSERT_TRUE(address_1_expiry < callback_data.aaaa_address.expiry);
    ASSERT_TRUE(address_1_expiry < callback_data.a_address.expiry);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* let it re-resolve, we should get addr 2 back, but with a later expiry than before.. */

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    /* here address 1 should still be the one returned because though we re-resolved, we don't trust the dns entries yet
     * and we kept them as bad addresses. */
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr2_ipv4, callback_data.a_address.address));
    ASSERT_TRUE(address_2_expiry < callback_data.aaaa_address.expiry);
    ASSERT_TRUE(address_2_expiry < callback_data.a_address.expiry);
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);
    aws_string_destroy((void *)host_name);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_ttl_refreshes_on_resolve, s_test_resolver_ttl_refreshes_on_resolve_fn)

static int s_test_resolver_ipv4_address_lookup_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "127.0.0.1");
    ASSERT_NOT_NULL(host_name);

    struct aws_host_resolution_config config = {
        .max_ttl = 10,
        .impl = aws_default_dns_resolve,
        .impl_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_TRUE(callback_data.has_a_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, callback_data.a_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name),
        host_name->len,
        aws_string_bytes(callback_data.a_address.host),
        callback_data.a_address.host->len);
    ASSERT_TRUE(callback_data.a_address.address->len > 1);
    ASSERT_FALSE(callback_data.has_aaaa_address);

    aws_host_address_clean_up(&callback_data.a_address);
    aws_mutex_unlock(&mutex);

    aws_string_destroy((void *)host_name);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(test_resolver_ipv4_address_lookup, s_test_resolver_ipv4_address_lookup_fn)

static int s_test_resolver_ipv6_address_lookup_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "::1");
    ASSERT_NOT_NULL(host_name);

    struct aws_host_resolution_config config = {
        .max_ttl = 10,
        .impl = aws_default_dns_resolve,
        .impl_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_FALSE(callback_data.has_a_address);
    ASSERT_TRUE(callback_data.has_aaaa_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_AAAA, callback_data.aaaa_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name),
        host_name->len,
        aws_string_bytes(callback_data.aaaa_address.host),
        callback_data.aaaa_address.host->len);
    ASSERT_TRUE(callback_data.aaaa_address.address->len > 1);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_mutex_unlock(&mutex);

    aws_string_destroy((void *)host_name);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(test_resolver_ipv6_address_lookup, s_test_resolver_ipv6_address_lookup_fn)

struct listener_test_callback_type_data {
    struct aws_allocator *allocator;
    bool callback_invoked;
    uint32_t error_code;
    uint32_t expected_num_addresses;
    struct aws_array_list address_list;
};

struct listener_test_callback_data {
    struct aws_allocator *allocator;
    struct aws_condition_variable condition_variable;
    struct aws_mutex *mutex;

    bool shutdown_invoked;
    struct listener_test_callback_type_data new_address_callback_data;
    struct listener_test_callback_type_data expired_address_callback_data;
};

static bool s_listener_new_address_invoked_predicate(void *data) {
    struct listener_test_callback_data *callback_data = data;
    return callback_data->new_address_callback_data.callback_invoked;
}

static bool s_listener_expired_address_invoked_predicate(void *data) {
    struct listener_test_callback_data *callback_data = data;
    return callback_data->expired_address_callback_data.callback_invoked;
}

static bool s_listener_new_address_complete_set_predicate(void *data) {
    struct listener_test_callback_data *callback_data = data;
    return callback_data->new_address_callback_data.callback_invoked &&
           aws_array_list_length(&callback_data->new_address_callback_data.address_list) ==
               callback_data->new_address_callback_data.expected_num_addresses;
}

static bool s_listener_expired_address_complete_set_predicate(void *data) {
    struct listener_test_callback_data *callback_data = data;
    return callback_data->expired_address_callback_data.callback_invoked &&
           aws_array_list_length(&callback_data->expired_address_callback_data.address_list) ==
               callback_data->expired_address_callback_data.expected_num_addresses;
}

static bool s_listener_shutdown_invoked_predicate(void *data) {
    struct listener_test_callback_data *callback_data = data;
    return callback_data->shutdown_invoked;
}

static void s_listener_test_callback_type_data_init(
    struct listener_test_callback_type_data *callback_data,
    struct aws_allocator *allocator,
    uint32_t expected_num_addresses) {
    callback_data->expected_num_addresses = expected_num_addresses;

    aws_array_list_init_dynamic(&callback_data->address_list, allocator, 4, sizeof(struct aws_host_address *));
}

static void s_listener_test_callback_data_init(
    struct aws_allocator *allocator,
    struct aws_mutex *mutex,
    uint32_t expected_new_addresses,
    uint32_t expected_expired_addresses,
    struct listener_test_callback_data *callback_data) {

    AWS_ZERO_STRUCT(*callback_data);

    callback_data->allocator = allocator;
    aws_condition_variable_init(&callback_data->condition_variable);
    callback_data->mutex = mutex;

    s_listener_test_callback_type_data_init(
        &callback_data->new_address_callback_data, allocator, expected_new_addresses);
    s_listener_test_callback_type_data_init(
        &callback_data->expired_address_callback_data, allocator, expected_expired_addresses);
}

static void s_clear_host_address_array_list(struct aws_array_list *host_address_array_list) {

    for (size_t i = 0; i < aws_array_list_length(host_address_array_list); ++i) {
        struct aws_host_address *host_address = NULL;
        aws_array_list_get_at(host_address_array_list, &host_address, i);

        if (host_address != NULL) {
            struct aws_allocator *allocator = host_address->allocator;

            aws_host_address_clean_up(host_address);
            aws_mem_release(allocator, host_address);
        }
    }

    aws_array_list_clear(host_address_array_list);
}

static void s_listener_test_callback_type_data_clean_up(struct listener_test_callback_type_data *callback_data) {
    s_clear_host_address_array_list(&callback_data->address_list);
    aws_array_list_clean_up(&callback_data->address_list);
}

static void s_listener_test_callback_data_clean_up(struct listener_test_callback_data *callback_data) {
    s_listener_test_callback_type_data_clean_up(&callback_data->new_address_callback_data);
    s_listener_test_callback_type_data_clean_up(&callback_data->expired_address_callback_data);
}

static void s_listener_address_callback(
    struct listener_test_callback_data *callback_data,
    struct listener_test_callback_type_data *callback_type_data,
    const struct aws_array_list *address_list) {

    bool expected_num_addresses_received = false;

    aws_mutex_lock(callback_data->mutex);
    callback_type_data->callback_invoked = true;

    size_t address_count = aws_array_list_length(address_list);
    for (size_t address_index = 0; address_index < address_count; ++address_index) {
        struct aws_host_address *host_address = NULL;

        aws_array_list_get_at_ptr(address_list, (void **)&host_address, address_index);

        struct aws_host_address *host_address_copy =
            aws_mem_acquire(callback_data->allocator, sizeof(struct aws_host_address));

        aws_host_address_copy(host_address, host_address_copy);

        aws_array_list_push_back(&callback_type_data->address_list, &host_address_copy);
    }

    expected_num_addresses_received =
        aws_array_list_length(&callback_type_data->address_list) == callback_type_data->expected_num_addresses;

    AWS_LOGF_INFO(
        AWS_LS_IO_DNS,
        "Listener received callback for %d of %d addresses.",
        (uint32_t)address_count,
        (uint32_t)callback_type_data->expected_num_addresses);

    aws_mutex_unlock(callback_data->mutex);

    if (expected_num_addresses_received) {
        aws_condition_variable_notify_one(&callback_data->condition_variable);
    }
}

static void s_listener_new_address_callback(
    struct aws_host_listener *listener,
    const struct aws_array_list *new_address_list,
    void *user_data) {
    (void)listener;

    struct listener_test_callback_data *callback_data = user_data;
    struct listener_test_callback_type_data *callback_type_data = &callback_data->new_address_callback_data;

    AWS_LOGF_INFO(AWS_LS_IO_DNS, "Listener new address callback.");

    s_listener_address_callback(callback_data, callback_type_data, new_address_list);
}

static void s_listener_expired_address_callback(
    struct aws_host_listener *listener,
    const struct aws_array_list *expired_address_list,
    void *user_data) {
    (void)listener;

    struct listener_test_callback_data *callback_data = user_data;
    struct listener_test_callback_type_data *callback_type_data = &callback_data->expired_address_callback_data;

    AWS_LOGF_INFO(AWS_LS_IO_DNS, "Listener expired address callback.");

    s_listener_address_callback(callback_data, callback_type_data, expired_address_list);
}

/* For test cases where we don't care at all about the result of the initial non-listener resolver callback. */
void s_listener_test_initial_resolved_callback_empty(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {
    (void)resolver;
    (void)host_name;
    (void)err_code;
    (void)host_addresses;
    (void)user_data;
}

/* Setup a mock host resolver with the specified test host name and number of addresses. */
static int s_setup_mock_host(
    struct aws_allocator *allocator,
    struct aws_host_resolver *resolver,
    struct mock_dns_resolver *mock_resolver,
    struct aws_string *host_name,
    uint32_t num_ipv4,
    uint32_t num_ipv6,
    uint32_t max_num_resolves) {

    (void)resolver;

    struct aws_array_list address_list;

    ASSERT_SUCCESS(
        aws_array_list_init_dynamic(&address_list, allocator, num_ipv4 + num_ipv6, sizeof(struct aws_host_address)));

    for (uint32_t i = 0; i < num_ipv4; ++i) {

        char address_buffer[128] = "";
        snprintf(address_buffer, sizeof(address_buffer), "test_address_%d_ipv4", i);

        struct aws_host_address host_address_ipv4 = {
            .address = aws_string_new_from_c_str(allocator, address_buffer),
            .allocator = allocator,
            .expiry = 0,
            .host = aws_string_new_from_string(allocator, host_name),
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_A,
            .use_count = 0,
            .weight = 0,
        };

        ASSERT_SUCCESS(aws_array_list_push_back(&address_list, &host_address_ipv4));
    }

    for (uint32_t i = 0; i < num_ipv6; ++i) {
        char address_buffer[128] = "";
        snprintf(address_buffer, sizeof(address_buffer), "test_address_%d_ipv6", i);

        struct aws_host_address host_address_ipv6 = {
            .address = aws_string_new_from_c_str(allocator, address_buffer),
            .allocator = allocator,
            .expiry = 0,
            .host = aws_string_new_from_string(allocator, host_name),
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
            .use_count = 0,
            .weight = 0,
        };

        ASSERT_SUCCESS(aws_array_list_push_back(&address_list, &host_address_ipv6));
    }

    ASSERT_SUCCESS(mock_dns_resolver_init(mock_resolver, max_num_resolves, allocator));
    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(mock_resolver, &address_list));

    return AWS_OP_SUCCESS;
}

/* Verify that a list of addresses has the expected number of ipv4 and ipv6 addresses, and has no duplicates. */
static int s_verify_mock_address_list(
    struct aws_array_list *address_list,
    uint32_t expected_num_ipv4,
    uint32_t expected_num_ipv6) {

    /* We shouldn't have any more addresses than the sum of our expected amount. */
    ASSERT_TRUE(aws_array_list_length(address_list) == (expected_num_ipv4 + expected_num_ipv6));

    uint32_t num_ipv4 = 0;
    uint32_t num_ipv6 = 0;

    /* Make sure we have the expected number of ipv4 and ipv6 addresses. */
    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *host_address = NULL;
        ASSERT_SUCCESS(aws_array_list_get_at(address_list, &host_address, i));

        if (host_address->record_type == AWS_ADDRESS_RECORD_TYPE_A) {
            ++num_ipv4;
        } else if (host_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA) {
            ++num_ipv6;
        } else {
            AWS_FATAL_ASSERT(false);
        }
    }

    ASSERT_TRUE(num_ipv4 == expected_num_ipv4);
    ASSERT_TRUE(num_ipv6 == expected_num_ipv6);

    /* Make sure we don't have any duplicates. This is n^2, but list size is expected to be small, and this is only used
     * for testing. */
    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *host_address0 = NULL;
        ASSERT_SUCCESS(aws_array_list_get_at(address_list, &host_address0, i));
        struct aws_byte_cursor address_byte_cursor0 = aws_byte_cursor_from_string(host_address0->address);

        for (size_t j = 0; j < aws_array_list_length(address_list); ++j) {
            if (i == j) {
                continue;
            }

            struct aws_host_address *host_address1 = NULL;
            ASSERT_SUCCESS(aws_array_list_get_at(address_list, &host_address1, j));
            struct aws_byte_cursor address_byte_cursor1 = aws_byte_cursor_from_string(host_address1->address);

            ASSERT_FALSE(aws_byte_cursor_eq(&address_byte_cursor0, &address_byte_cursor1));
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_verify_address_in_list(
    struct aws_array_list *address_list,
    struct aws_byte_cursor address,
    enum aws_address_record_type address_type) {

    /* Check for address in list */
    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *host_address = NULL;
        ASSERT_SUCCESS(aws_array_list_get_at(address_list, &host_address, i));

        if (host_address->record_type != address_type) {
            continue;
        }

        struct aws_byte_cursor record_address = aws_byte_cursor_from_string(host_address->address);
        if (!aws_byte_cursor_eq(&address, &record_address)) {
            continue;
        }

        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

static void s_listener_shutdown_callback(void *user_data) {
    struct listener_test_callback_data *callback_data = user_data;

    aws_mutex_lock(callback_data->mutex);
    callback_data->shutdown_invoked = true;
    aws_mutex_unlock(callback_data->mutex);

    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static void s_wait_on_listener_shutdown(struct listener_test_callback_data *callback_data) {
    aws_mutex_lock(callback_data->mutex);

    aws_condition_variable_wait_pred(
        &callback_data->condition_variable, callback_data->mutex, s_listener_shutdown_invoked_predicate, callback_data);

    aws_mutex_unlock(callback_data->mutex);
}

static int s_test_resolver_listener_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test_host");
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;
    s_listener_test_callback_data_init(allocator, &mutex, 0, 0, &callback_data);

    /* Setup listener and then release the listener */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
        aws_host_resolver_remove_host_listener(resolver, listener);
        listener = NULL;
    }

    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    s_listener_test_callback_data_clean_up(&callback_data);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_resolver_listener_create_destroy, s_test_resolver_listener_create_destroy_fn)

static int s_test_resolver_add_listener_before_host_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3.us-east-1.amazonaws.com");
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;

    s_listener_test_callback_data_init(allocator, &mutex, 1, 0, &callback_data);

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 1,
            .impl = aws_default_dns_resolve,
            .impl_data = NULL,
        };

        struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_listener_test_initial_resolved_callback_empty, &config, NULL));

        aws_string_destroy(host_name_str);
    }

    /* Wait for listener to receive host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.new_address_callback_data.callback_invoked = false;

        ASSERT_TRUE(aws_array_list_length(&callback_data.new_address_callback_data.address_list) > 0);

        aws_mutex_unlock(&mutex);
    }

    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;

    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    s_listener_test_callback_data_clean_up(&callback_data);
    aws_mutex_clean_up(&mutex);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_resolver_add_listener_before_host, s_test_resolver_add_listener_before_host_fn)

/* Callback used for waiting until the initial host resolution has completed. */
void s_listener_test_initial_resolved_callback_wait(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {

    (void)resolver;
    (void)host_name;
    (void)err_code;
    (void)host_addresses;

    struct listener_test_callback_data *callback_data = user_data;

    aws_mutex_lock(callback_data->mutex);
    callback_data->new_address_callback_data.callback_invoked = true;
    aws_mutex_unlock(callback_data->mutex);

    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static int s_test_resolver_add_listener_after_host_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3.us-east-1.amazonaws.com");
    struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;
    s_listener_test_callback_data_init(allocator, &mutex, 1, 0, &callback_data);

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 30,
            .impl = aws_default_dns_resolve,
            .impl_data = NULL,
        };

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_listener_test_initial_resolved_callback_wait, &config, &callback_data));

        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.new_address_callback_data.callback_invoked = false;

        aws_mutex_unlock(&mutex);
    }

    /* Setup listener after host is added */
    {

        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    /* Wait for listeners to receive host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.new_address_callback_data.callback_invoked = false;

        ASSERT_TRUE(aws_array_list_length(&callback_data.new_address_callback_data.address_list) > 0);

        aws_mutex_unlock(&mutex);
    }

    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;

    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    s_listener_test_callback_data_clean_up(&callback_data);
    aws_mutex_clean_up(&mutex);
    aws_string_destroy(host_name_str);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_resolver_add_listener_after_host, s_test_resolver_add_listener_after_host_fn)

static int s_test_resolver_add_multiple_listeners_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("s3.us-east-1.amazonaws.com");
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener1 = NULL;
    struct aws_host_listener *listener2 = NULL;

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data1;
    struct listener_test_callback_data callback_data2;

    s_listener_test_callback_data_init(allocator, &mutex, 1, 0, &callback_data1);
    s_listener_test_callback_data_init(allocator, &mutex, 1, 0, &callback_data2);

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options1 = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data1,
        };

        listener1 = aws_host_resolver_add_host_listener(resolver, &listener_options1);

        struct aws_host_listener_options listener_options2 = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data2,
        };

        listener2 = aws_host_resolver_add_host_listener(resolver, &listener_options2);
    }

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 1,
            .impl = aws_default_dns_resolve,
            .impl_data = NULL,
        };

        struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_listener_test_initial_resolved_callback_empty, &config, NULL));

        aws_string_destroy(host_name_str);
    }

    /* Wait for listener to receive host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data1.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data1);

        /* Reset flag for re-use */
        callback_data1.new_address_callback_data.callback_invoked = false;

        aws_condition_variable_wait_pred(
            &callback_data2.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data2);

        /* Reset flag for re-use */
        callback_data2.new_address_callback_data.callback_invoked = false;

        ASSERT_TRUE(aws_array_list_length(&callback_data1.new_address_callback_data.address_list) > 0);
        ASSERT_TRUE(aws_array_list_length(&callback_data2.new_address_callback_data.address_list) > 0);

        aws_mutex_unlock(&mutex);
    }

    aws_host_resolver_remove_host_listener(resolver, listener1);
    listener1 = NULL;

    aws_host_resolver_remove_host_listener(resolver, listener2);
    listener2 = NULL;

    s_wait_on_listener_shutdown(&callback_data1);
    s_wait_on_listener_shutdown(&callback_data2);

    aws_host_resolver_release(resolver);

    s_listener_test_callback_data_clean_up(&callback_data1);
    s_listener_test_callback_data_clean_up(&callback_data2);
    aws_mutex_clean_up(&mutex);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(test_resolver_add_multiple_listeners_fn, s_test_resolver_add_multiple_listeners_fn)

/* Test to make sure that a host listener still works even when a host entry is removed and re-added. */
static int s_test_resolver_listener_host_re_add_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    const uint32_t num_ipv4 = 1;
    const uint32_t num_ipv6 = 1;
    const size_t max_ttl_seconds = 1;

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test_host");
    struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;

    s_listener_test_callback_data_init(allocator, &mutex, num_ipv4 + num_ipv6, 0, &callback_data);

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    /* Trigger resolve host */
    struct mock_dns_resolver mock_resolver_0;
    ASSERT_SUCCESS(s_setup_mock_host(allocator, resolver, &mock_resolver_0, host_name_str, num_ipv4, num_ipv6, 1));

    struct aws_host_resolution_config config_0 = {
        .max_ttl = max_ttl_seconds,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver_0,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_str, s_listener_test_initial_resolved_callback_empty, &config_0, NULL));

    /* Wait for listener to receive host resolved callback. */
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

    /* Reset flag for re-use */
    callback_data.new_address_callback_data.callback_invoked = false;

    ASSERT_SUCCESS(
        s_verify_mock_address_list(&callback_data.new_address_callback_data.address_list, num_ipv4, num_ipv6));

    aws_mutex_unlock(&mutex);

    s_listener_test_callback_data_clean_up(&callback_data);
    s_listener_test_callback_data_init(allocator, &mutex, num_ipv4 + num_ipv6, 0, &callback_data);

    /* Wait for TTL + half a second so that the host gets completely removed. */
    {
        const uint64_t half_second_in_millseconds = 500;
        const uint64_t wait_interval =
            aws_timestamp_convert(max_ttl_seconds, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL) +
            aws_timestamp_convert(half_second_in_millseconds, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);

        aws_thread_current_sleep(wait_interval);
    }

    size_t address_count = aws_host_resolver_get_host_address_count(
        resolver,
        host_name_str,
        AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);

    /* If the host is really gone, we shouldn't have any addresses. */
    ASSERT_TRUE(address_count == 0);

    /* Trigger resolve host with a new mock resolver, effectively re-adding the host. */
    struct mock_dns_resolver mock_resolver_1;
    ASSERT_SUCCESS(s_setup_mock_host(allocator, resolver, &mock_resolver_1, host_name_str, num_ipv4, num_ipv6, 1));

    struct aws_host_resolution_config config_1 = {
        .max_ttl = max_ttl_seconds,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver_1,
    };

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_str, s_listener_test_initial_resolved_callback_empty, &config_1, NULL));

    /* Wait for listener to receive host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.new_address_callback_data.callback_invoked = false;

        ASSERT_SUCCESS(
            s_verify_mock_address_list(&callback_data.new_address_callback_data.address_list, num_ipv4, num_ipv6));

        aws_mutex_unlock(&mutex);
    }

    s_listener_test_callback_data_clean_up(&callback_data);
    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;

    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    aws_mutex_clean_up(&mutex);
    aws_string_destroy(host_name_str);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver_0);
    mock_dns_resolver_clean_up(&mock_resolver_1);

    return 0;
}

AWS_TEST_CASE(test_resolver_listener_host_re_add_fn, s_test_resolver_listener_host_re_add_fn)

static int s_test_resolver_listener_multiple_results_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    const uint32_t num_ipv4 = 4;
    const uint32_t num_ipv6 = 4;
    const uint32_t max_num_resolves = 1;

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test_host");
    struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(
        s_setup_mock_host(allocator, resolver, &mock_resolver, host_name_str, num_ipv4, num_ipv6, max_num_resolves));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;

    s_listener_test_callback_data_init(allocator, &mutex, num_ipv4 + num_ipv6, 0, &callback_data);

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 30,
            .impl = mock_dns_resolve,
            .impl_data = &mock_resolver,
        };

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_listener_test_initial_resolved_callback_empty, &config, NULL));
    }

    /* Wait for listener to receive host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.new_address_callback_data.callback_invoked = false;

        ASSERT_SUCCESS(
            s_verify_mock_address_list(&callback_data.new_address_callback_data.address_list, num_ipv4, num_ipv6));

        aws_mutex_unlock(&mutex);
    }

    s_listener_test_callback_data_clean_up(&callback_data);
    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;

    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    aws_mutex_clean_up(&mutex);
    aws_string_destroy(host_name_str);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_listener_multiple_results, s_test_resolver_listener_multiple_results_fn)

static uint64_t s_mocked_time = 0;
static struct aws_mutex s_mocked_time_lock = AWS_MUTEX_INIT;

int s_get_mock_system_clock(uint64_t *timestamp) {
    aws_mutex_lock(&s_mocked_time_lock);
    *timestamp = s_mocked_time;
    aws_mutex_unlock(&s_mocked_time_lock);

    return AWS_OP_SUCCESS;
}

void s_set_mock_system_clock(uint64_t timestamp) {
    aws_mutex_lock(&s_mocked_time_lock);
    s_mocked_time = timestamp;
    aws_mutex_unlock(&s_mocked_time_lock);
}

static int s_test_resolver_listener_address_expired_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    const uint32_t num_ipv4 = 4;
    const uint32_t num_ipv6 = 4;
    const uint32_t max_num_resolves = 1;

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test_host");
    struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
        .system_clock_override_fn = s_get_mock_system_clock,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(
        s_setup_mock_host(allocator, resolver, &mock_resolver, host_name_str, num_ipv4, num_ipv6, max_num_resolves));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;

    /*
     * Internal default resolver detail: we don't expire the last remaining address, so we expect to see
     * everything but one in each of the a and aaaa lists expire.
     */
    uint32_t expected_expirations = num_ipv4 + num_ipv6 - 2;
    s_listener_test_callback_data_init(allocator, &mutex, num_ipv4 + num_ipv6, expected_expirations, &callback_data);

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .resolved_address_callback = s_listener_new_address_callback,
            .expired_address_callback = s_listener_expired_address_callback,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 30,
            .impl = mock_dns_resolve,
            .impl_data = &mock_resolver,
        };

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_listener_test_initial_resolved_callback_empty, &config, NULL));
    }

    /* Wait for listener to receive host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_new_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.new_address_callback_data.callback_invoked = false;

        ASSERT_SUCCESS(
            s_verify_mock_address_list(&callback_data.new_address_callback_data.address_list, num_ipv4, num_ipv6));
        ASSERT_INT_EQUALS(0, aws_array_list_length(&callback_data.expired_address_callback_data.address_list));

        aws_mutex_unlock(&mutex);
    }

    /* advance time far enough that the addresses should expire */
    uint64_t expiration_time = aws_timestamp_convert(30, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL) + 1;
    s_set_mock_system_clock(expiration_time);

    /* Wait for listener to receive address expired callback */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &callback_data.condition_variable, &mutex, s_listener_expired_address_invoked_predicate, &callback_data);

        /* Reset flag for re-use */
        callback_data.expired_address_callback_data.callback_invoked = false;

        ASSERT_SUCCESS(s_verify_mock_address_list(
            &callback_data.expired_address_callback_data.address_list, num_ipv4 - 1, num_ipv6 - 1));

        aws_mutex_unlock(&mutex);
    }

    s_listener_test_callback_data_clean_up(&callback_data);
    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;
    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    aws_mutex_clean_up(&mutex);
    aws_string_destroy(host_name_str);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_listener_address_expired_fn, s_test_resolver_listener_address_expired_fn)

/*
 * This test works on the following assumption:
 *
 * Failed resolves will always generate a callback from the host's resolution thread (not true for successful
 * resolves, and new/expired callbacks are unreliable to generate on a pinned resolver).  So we can test
 * whether or not a host entry is successfully pinned by making two failure-bound resolution calls inbetween
 * a wait that is substantially longer than the TTL of the resolution and then checking the thread ids captured
 * in the two callbacks.  If they're different, we know that the resolution thread was destroyed and remade; if
 * they're the same, we know the resolution thread was successfully pinned.
 */
static int s_test_host_entry_pinning(struct aws_allocator *allocator, bool pin_host_entry) {
    aws_io_library_init(allocator);

    struct aws_byte_cursor host_name = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("test_host");
    struct aws_string *host_name_str = aws_string_new_from_c_str(allocator, (const char *)host_name.ptr);
    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);
    struct aws_host_listener *listener = NULL;

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(s_setup_mock_host(allocator, resolver, &mock_resolver, host_name_str, 0, 0, 0));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data callback_data;
    s_listener_test_callback_data_init(allocator, &mutex, 0, 0, &callback_data);

    struct default_host_callback_data resolve_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = host_name,
            .shutdown_callback = s_listener_shutdown_callback,
            .user_data = &callback_data,
            .pin_host_entry = pin_host_entry,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    aws_thread_id_t first_thread_id;

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 1,
            .impl = mock_dns_resolve,
            .impl_data = &mock_resolver,
        };

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_default_host_resolved_test_callback, &config, &resolve_callback_data));
    }

    /* Wait for listener to receive (failed) host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &resolve_callback_data.condition_variable,
            &mutex,
            s_default_host_resolved_predicate,
            &resolve_callback_data);

        first_thread_id = resolve_callback_data.callback_thread_id;
        resolve_callback_data.invoked = false;

        aws_mutex_unlock(&mutex);
    }

    aws_thread_current_sleep(aws_timestamp_convert(3, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    aws_thread_id_t second_thread_id;

    /* Trigger resolve host */
    {
        struct aws_host_resolution_config config = {
            .max_ttl = 1,
            .impl = mock_dns_resolve,
            .impl_data = &mock_resolver,
        };

        ASSERT_SUCCESS(aws_host_resolver_resolve_host(
            resolver, host_name_str, s_default_host_resolved_test_callback, &config, &resolve_callback_data));
    }

    /* Wait for listener to receive (failed) host resolved callback. */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&mutex));

        aws_condition_variable_wait_pred(
            &resolve_callback_data.condition_variable,
            &mutex,
            s_default_host_resolved_predicate,
            &resolve_callback_data);

        second_thread_id = resolve_callback_data.callback_thread_id;

        aws_mutex_unlock(&mutex);
    }

    /* compare the two thread ids */
    ASSERT_TRUE(aws_thread_thread_id_equal(first_thread_id, second_thread_id) == pin_host_entry);

    s_listener_test_callback_data_clean_up(&callback_data);
    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;
    s_wait_on_listener_shutdown(&callback_data);

    aws_host_resolver_release(resolver);

    aws_mutex_clean_up(&mutex);
    aws_string_destroy(host_name_str);

    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return AWS_OP_SUCCESS;
}

static int s_test_resolver_pinned_host_entry(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_test_host_entry_pinning(allocator, true));

    return 0;
}

AWS_TEST_CASE(test_resolver_pinned_host_entry, s_test_resolver_pinned_host_entry)

static int s_test_resolver_unpinned_host_entry(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_test_host_entry_pinning(allocator, false));

    return 0;
}

AWS_TEST_CASE(test_resolver_unpinned_host_entry, s_test_resolver_unpinned_host_entry)

/*
 * A variant of the connect_failure_recording test that checks to see if failed addresses that are
 * re-promoted to good end up invoking the new address listener callback.  Also checks that failed
 * addresses invoke the expiration callback
 */
static int s_test_resolver_address_promote_demote_listener_callbacks_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group,
        .max_entries = 10,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_new_from_c_str(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_new_from_c_str(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_new_from_c_str(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_new_from_c_str(allocator, "address2ipv6");

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_resolver, 1000, allocator));

    struct aws_host_resolution_config config = {
        .max_ttl = 30,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver,
    };

    struct aws_host_address host_address_1_ipv4 = {
        .address = addr1_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_1_ipv6 = {
        .address = addr1_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv4 = {
        .address = addr2_ipv4,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2_ipv6 = {
        .address = addr2_ipv6,
        .allocator = allocator,
        .expiry = 0,
        .host = aws_string_new_from_c_str(allocator, "host_address"),
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_array_list address_list_1;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_1, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv4));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv4));

    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_resolver, &address_list_1));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct listener_test_callback_data listener_callback_data;
    s_listener_test_callback_data_init(allocator, &mutex, 4, 2, &listener_callback_data);
    struct aws_host_listener *listener = NULL;

    /* Setup listener before host is added */
    {
        struct aws_host_listener_options listener_options = {
            .host_name = aws_byte_cursor_from_string(host_name),
            .shutdown_callback = s_listener_shutdown_callback,
            .resolved_address_callback = s_listener_new_address_callback,
            .expired_address_callback = s_listener_expired_address_callback,
            .user_data = &listener_callback_data,
            .pin_host_entry = true,
        };

        listener = aws_host_resolver_add_host_listener(resolver, &listener_options);
    }

    struct default_host_callback_data resolve_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .has_aaaa_address = false,
        .has_a_address = false,
        .mutex = &mutex,
    };

    /*
     * Resolve #1
     * Wait on new_address listener callback, should get 4 new addresses
     */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_listener_test_initial_resolved_callback_empty, &config, NULL));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    aws_condition_variable_wait_pred(
        &listener_callback_data.condition_variable,
        &mutex,
        s_listener_new_address_invoked_predicate,
        &listener_callback_data);

    /* Check new address data */
    ASSERT_INT_EQUALS(4, aws_array_list_length(&listener_callback_data.new_address_callback_data.address_list));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.new_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr1_ipv4),
        AWS_ADDRESS_RECORD_TYPE_A));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.new_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr1_ipv6),
        AWS_ADDRESS_RECORD_TYPE_AAAA));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.new_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr2_ipv4),
        AWS_ADDRESS_RECORD_TYPE_A));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.new_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr2_ipv6),
        AWS_ADDRESS_RECORD_TYPE_AAAA));

    /* Reset new address data */
    s_clear_host_address_array_list(&listener_callback_data.new_address_callback_data.address_list);
    listener_callback_data.new_address_callback_data.callback_invoked = false;

    aws_mutex_unlock(&mutex);

    /*
     * Resolve #2
     * Wait on resolver callback (will be a previously seen address)
     * Then fail address 1 both ipv6 and ipv4
     */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &resolve_callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &resolve_callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &resolve_callback_data);

    aws_host_address_clean_up(&resolve_callback_data.aaaa_address);
    aws_host_address_clean_up(&resolve_callback_data.a_address);
    resolve_callback_data.invoked = false;

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_1_ipv4));

    /* should not see any new or expired addresses at this point */
    ASSERT_FALSE(listener_callback_data.new_address_callback_data.callback_invoked);
    ASSERT_FALSE(listener_callback_data.expired_address_callback_data.callback_invoked);

    aws_mutex_unlock(&mutex);

    /*
     * Resolve #3
     * Following the LRU policy, address 1 should be what gets returned here, however we marked it as failed, so it
     * should be skipped and address 2 should be returned.
     *
     * We should also get expiration notices for the two failed addresses
     */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &resolve_callback_data));

    aws_mutex_lock(&mutex);

    /*
     * Wait for both expiration and resolution completion
     */
    aws_condition_variable_wait_pred(
        &resolve_callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &resolve_callback_data);

    aws_condition_variable_wait_pred(
        &listener_callback_data.condition_variable,
        &mutex,
        s_listener_expired_address_invoked_predicate,
        &listener_callback_data);

    aws_host_address_clean_up(&resolve_callback_data.aaaa_address);
    aws_host_address_clean_up(&resolve_callback_data.a_address);
    resolve_callback_data.invoked = false;

    /*
     * Check listener callback data.  We expect two expired addresses due to failure and no new addresses.
     */
    ASSERT_INT_EQUALS(2, aws_array_list_length(&listener_callback_data.expired_address_callback_data.address_list));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.expired_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr1_ipv4),
        AWS_ADDRESS_RECORD_TYPE_A));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.expired_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr1_ipv6),
        AWS_ADDRESS_RECORD_TYPE_AAAA));

    ASSERT_FALSE(listener_callback_data.new_address_callback_data.callback_invoked);

    listener_callback_data.expired_address_callback_data.callback_invoked = false;
    s_clear_host_address_array_list(&listener_callback_data.expired_address_callback_data.address_list);

    /*
     * Prep for the new address callbacks which we should receive when the failed ones get promoted
     * next resolve.
     */
    listener_callback_data.new_address_callback_data.callback_invoked = false;
    listener_callback_data.new_address_callback_data.expected_num_addresses = 2;

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_2_ipv4));

    aws_mutex_unlock(&mutex);

    /*
     * Resolve #4
     * By failing address2 previously, all addresses should now be failed.  In response, the resolver should
     * promote address 1 back to a good state.  So we should see
     *   (1) 2 expired addresses (from the fail calls above)
     *   (2) 2 new addresses (previously failed addresses promoted out of desperation)
     */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &resolve_callback_data));

    /* here address 1 should be returned since it is now the least recently used address and all of them have failed..
     */
    aws_mutex_lock(&mutex);

    /*
     * Wait for resolution, expiration, and new listener callbacks
     */
    aws_condition_variable_wait_pred(
        &resolve_callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &resolve_callback_data);

    aws_condition_variable_wait_pred(
        &listener_callback_data.condition_variable,
        &mutex,
        s_listener_new_address_complete_set_predicate,
        &listener_callback_data);

    aws_condition_variable_wait_pred(
        &listener_callback_data.condition_variable,
        &mutex,
        s_listener_expired_address_complete_set_predicate,
        &listener_callback_data);

    aws_host_address_clean_up(&resolve_callback_data.aaaa_address);
    aws_host_address_clean_up(&resolve_callback_data.a_address);

    /*
     * Check new address callback data
     */
    ASSERT_TRUE(2 == aws_array_list_length(&listener_callback_data.new_address_callback_data.address_list));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.new_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr1_ipv4),
        AWS_ADDRESS_RECORD_TYPE_A));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.new_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr1_ipv6),
        AWS_ADDRESS_RECORD_TYPE_AAAA));

    /*
     * Check expired address callback data
     */
    ASSERT_TRUE(2 == aws_array_list_length(&listener_callback_data.expired_address_callback_data.address_list));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.expired_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr2_ipv4),
        AWS_ADDRESS_RECORD_TYPE_A));
    ASSERT_SUCCESS(s_verify_address_in_list(
        &listener_callback_data.expired_address_callback_data.address_list,
        aws_byte_cursor_from_string(addr2_ipv6),
        AWS_ADDRESS_RECORD_TYPE_AAAA));

    aws_mutex_unlock(&mutex);

    s_listener_test_callback_data_clean_up(&listener_callback_data);
    aws_host_resolver_remove_host_listener(resolver, listener);
    listener = NULL;
    s_wait_on_listener_shutdown(&listener_callback_data);

    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    aws_string_destroy((void *)host_name);
    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(
    test_resolver_address_promote_demote_listener_callbacks,
    s_test_resolver_address_promote_demote_listener_callbacks_fn)

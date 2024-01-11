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

static void s_default_host_purge_callback(void *user_data) {
    struct default_host_callback_data *callback_data = user_data;
    aws_mutex_lock(callback_data->mutex);
    callback_data->invoked = true;
    callback_data->callback_thread_id = aws_thread_current_thread_id();
    aws_mutex_unlock(callback_data->mutex);
    aws_condition_variable_notify_one(&callback_data->condition_variable);
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
 * The first assumption is that ec2.us-east-1.amazonaws.com will never return an IPv6 address.
 * The second assumption is that the TTLs for these records are one second and that the backend resolver
 * resolves at the TTL rate.
 * The third assumption is that this test runs in less than one second after the first background resolve.
 * The fourth assumption is that ec2.us-east-1.api.aws does not return multiple addresses per A or AAAA record.
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

    const struct aws_string *host_name_1 = aws_string_new_from_c_str(allocator, "ec2.us-east-1.api.aws");
    const struct aws_string *host_name_2 = aws_string_new_from_c_str(allocator, "ec2.us-east-1.amazonaws.com");

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

static struct aws_mutex s_time_lock = AWS_MUTEX_INIT;
static uint64_t s_current_time = 0;

static int s_clock_fn(uint64_t *current_time) {
    aws_mutex_lock(&s_time_lock);
    *current_time = s_current_time;
    aws_mutex_unlock(&s_time_lock);

    return AWS_OP_SUCCESS;
}

static void s_set_time(uint64_t current_time) {
    aws_mutex_lock(&s_time_lock);
    s_current_time = current_time;
    aws_mutex_unlock(&s_time_lock);
}

static int s_test_resolver_ttls_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    s_set_time(0);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = el_group, .max_entries = 10, .system_clock_override_fn = s_clock_fn};
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_new_from_c_str(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_new_from_c_str(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_new_from_c_str(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_new_from_c_str(allocator, "address2ipv6");

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_resolver, 2, allocator));

    struct aws_host_resolution_config config = {
        .max_ttl = 2,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver,
        .resolve_frequency_ns = aws_timestamp_convert(500, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL)};

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

    /* t = 0s */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* bump us up to near expiration time, but not quite, t = 1.5s */
    s_set_time(aws_timestamp_convert(1500, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

    /* over-sleep; several resolves should run.  The second address should have an expiry time based on t = 1.5s */
    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    /*
     * We still get address 1 on the second resolve because address 2 was put as MRU when it was resolved on the
     * second iteration of the resolver loop.
     */
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* instantly requery, we should get address 2 (which was unfortunately dumped in the back of the lru cache on
     * resolution */
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

    /* bump us past expiration time, t = 2.001 */
    s_set_time(aws_timestamp_convert(2001, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

    /* over-sleep to allow the host resolver thread to run at least one more iteration to cull the expired record */
    aws_thread_current_sleep(FORCE_RESOLVE_SLEEP_TIME);

    /* note that normally, the first address would come back, but the TTL is expired (we set it to two seconds).
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

    /*
     * t = 4, all addresses should be expired
     */
    s_set_time(aws_timestamp_convert(4, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL));

    /* over-sleep so entry two expires. Now everything is expired, but because the last thing we resolved was addr 2, it
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

static int s_test_resolver_purge_host_cache(struct aws_allocator *allocator, void *ctx) {
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

    size_t address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);
    ASSERT_INT_EQUALS(address_count, 1);

    /* purge the host */
    struct aws_host_resolver_purge_host_options purge_host_options = {
        .host = host_name,
        .on_host_purge_complete_callback = s_default_host_purge_callback,
        .user_data = &callback_data,
    };
    ASSERT_SUCCESS(aws_host_resolver_purge_host_cache(resolver, &purge_host_options));
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);

    /* If the host is really gone, we shouldn't have any addresses. */
    ASSERT_INT_EQUALS(address_count, 0);

    /* try purging it again */
    ASSERT_SUCCESS(aws_host_resolver_purge_host_cache(resolver, &purge_host_options));
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    /* try adding the host again */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

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

    address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);
    ASSERT_INT_EQUALS(address_count, 1);

    aws_string_destroy((void *)host_name);
    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(test_resolver_purge_host_cache, s_test_resolver_purge_host_cache)

static int s_test_resolver_purge_cache(struct aws_allocator *allocator, void *ctx) {
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

    const struct aws_string *host_name_2 = aws_string_new_from_c_str(allocator, "127.0.0.2");
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

    /* resolve first host */
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

    /* resolve second host */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name_2, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_TRUE(callback_data.has_a_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, callback_data.a_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name_2),
        host_name->len,
        aws_string_bytes(callback_data.a_address.host),
        callback_data.a_address.host->len);
    ASSERT_TRUE(callback_data.a_address.address->len > 1);
    ASSERT_FALSE(callback_data.has_aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_mutex_unlock(&mutex);

    size_t address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);
    ASSERT_INT_EQUALS(address_count, 1);

    address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name_2, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);
    ASSERT_INT_EQUALS(address_count, 1);

    ASSERT_SUCCESS(
        aws_host_resolver_purge_cache_with_callback(resolver, s_default_host_purge_callback, &callback_data));
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);

    /* If the host is really gone, we shouldn't have any addresses. */
    ASSERT_INT_EQUALS(address_count, 0);

    address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name_2, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);

    /* If the host is really gone, we shouldn't have any addresses. */
    ASSERT_INT_EQUALS(address_count, 0);

    /* try purging it again */
    ASSERT_SUCCESS(
        aws_host_resolver_purge_cache_with_callback(resolver, s_default_host_purge_callback, &callback_data));
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);
    callback_data.invoked = false;
    aws_mutex_unlock(&mutex);

    /* try adding the host again */
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

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

    address_count = aws_host_resolver_get_host_address_count(
        resolver, host_name, AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA);
    ASSERT_INT_EQUALS(address_count, 1);

    aws_string_destroy((void *)host_name);
    aws_string_destroy((void *)host_name_2);

    aws_host_resolver_release(resolver);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return 0;
}
AWS_TEST_CASE(test_resolver_purge_cache, s_test_resolver_purge_cache)

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

static int s_test_resolver_low_frequency_starvation_fn(struct aws_allocator *allocator, void *ctx) {
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

    struct mock_dns_resolver mock_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_resolver, 1000, allocator));

    struct aws_host_resolution_config config = {
        .max_ttl = 30,
        .impl = mock_dns_resolve,
        .impl_data = &mock_resolver,
        .resolve_frequency_ns = aws_timestamp_convert(120, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL),
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

    struct aws_array_list address_list_1;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_1, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv4));

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

    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;

    aws_mutex_unlock(&mutex);

    uint64_t starvation_start = 0;
    aws_high_res_clock_get_ticks(&starvation_start);

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(resolver, &host_address_1_ipv4));

    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        resolver, host_name, s_default_host_resolved_test_callback, &config, &callback_data));

    aws_mutex_lock(&mutex);
    aws_condition_variable_wait_pred(
        &callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &callback_data);

    uint64_t starvation_end = 0;
    aws_high_res_clock_get_ticks(&starvation_end);

    uint64_t starvation_ms =
        aws_timestamp_convert(starvation_end - starvation_start, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL);

    /*
     * verify that the time it took to get a resolution was non-trivial (in this case we check half the minimum
     * between-resolve wait time) and also not huge (resolve frequency is two minutes after all)
     */
    ASSERT_TRUE(starvation_ms > 50);
    ASSERT_TRUE(starvation_ms < 1000);

    ASSERT_INT_EQUALS(0, aws_string_compare(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.a_address);

    aws_mutex_unlock(&mutex);

    aws_host_resolver_release(resolver);
    aws_string_destroy((void *)host_name);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    mock_dns_resolver_clean_up(&mock_resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_low_frequency_starvation, s_test_resolver_low_frequency_starvation_fn)

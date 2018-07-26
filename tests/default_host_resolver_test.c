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
#include <mock_dns_resolver.c>

#include <aws/io/host_resolver.h>
#include <aws/common/condition_variable.h>
#include <aws/common/thread.h>


struct default_host_callback_data {
    struct aws_host_address aaaa_address;
    struct aws_host_address a_address;
    bool has_aaaa_address;
    bool has_a_address;
    struct aws_condition_variable condition_variable;
    bool invoked;
};

static bool default_host_resolved_predicate (void *arg) {
    struct default_host_callback_data *callback_data = arg;

    return callback_data->invoked;
}

void default_host_resolved_test_callback (struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                          int err_code, const struct aws_array_list *host_addresses, void *user_data) {
    struct default_host_callback_data *callback_data = user_data;

    struct aws_host_address *host_address = NULL;

    if (aws_array_list_length(host_addresses) >= 2) {
        aws_array_list_get_at(host_addresses, &host_address, 0);

        aws_host_address_copy(host_address, &callback_data->aaaa_address);

        aws_array_list_get_at(host_addresses, &host_address, 1);

        aws_host_address_copy(host_address, &callback_data->a_address);
        callback_data->has_aaaa_address = true;
        callback_data->has_a_address = true;
    }
    else if (aws_array_list_length(host_addresses) == 1) {
        aws_array_list_get_at(host_addresses, &host_address, 0);

        aws_host_address_copy(host_address, &callback_data->a_address);
        callback_data->has_a_address = true;
    }

    callback_data->invoked = true;
    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static int test_default_with_ipv6_lookup_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_host_resolver resolver;

    ASSERT_SUCCESS(aws_host_resolver_default_init(&resolver, allocator, 10));

    const struct aws_string *host_name = aws_string_from_c_str_new(allocator, "s3.dualstack.us-east-1.amazonaws.com");
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
    };

    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_TRUE(callback_data.has_aaaa_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_AAAA, callback_data.aaaa_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(aws_string_bytes(host_name), host_name->len,
                             aws_string_bytes(callback_data.aaaa_address.host),
                             callback_data.aaaa_address.host->len);
    ASSERT_TRUE(callback_data.has_a_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, callback_data.a_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(aws_string_bytes(host_name), host_name->len,
                             aws_string_bytes(callback_data.a_address.host), callback_data.a_address.host->len);
    ASSERT_TRUE(callback_data.aaaa_address.address->len > 1);
    ASSERT_TRUE(callback_data.a_address.address->len > 1);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    aws_string_destroy((void *)host_name);
    aws_host_resolver_clean_up(&resolver);

    return 0;
}

AWS_TEST_CASE(test_default_with_ipv6_lookup, test_default_with_ipv6_lookup_fn)

/* just FYI, this test assumes that "s3.us-east-1.amazonaws.com" does not return IPv6 addresses. */
static int test_default_with_ipv4_only_lookup_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_host_resolver resolver;

    ASSERT_SUCCESS(aws_host_resolver_default_init(&resolver, allocator, 10));

    const struct aws_string *host_name = aws_string_from_c_str_new(allocator, "s3.us-east-1.amazonaws.com");
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
    };

    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_FALSE(callback_data.has_aaaa_address);
    ASSERT_TRUE(callback_data.has_a_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, callback_data.a_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(aws_string_bytes(host_name), host_name->len,
                             aws_string_bytes(callback_data.a_address.host), callback_data.a_address.host->len);
    ASSERT_TRUE(callback_data.a_address.address->len > 1);

    aws_host_address_clean_up(&callback_data.a_address);
    aws_string_destroy((void *)host_name);
    aws_host_resolver_clean_up(&resolver);

    return 0;
}

AWS_TEST_CASE(test_default_with_ipv4_only_lookup, test_default_with_ipv4_only_lookup_fn)

/* there are multiple big assumptions in this test.
 * The first assumption is that s3.us-east-1.amazonaws.com will never return an IPv6 address.
 * The second assumption is that the TTLs for these records are one second and that the backend resolver
 * resolves at the TTL rate.
 * The third assumption is that this test runs in less than one second after the first background resolve.
 * The fourth assumption is that S3 does not return multiple addresses per A or AAAA record.
 * If any of these assumptions ever change, this test will likely be broken, but I don't know of a better way to test this end-to-end. */
static int test_default_with_multiple_lookups_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_host_resolver resolver;

    ASSERT_SUCCESS(aws_host_resolver_default_init(&resolver, allocator, 10));

    const struct aws_string *host_name_1 = aws_string_from_c_str_new(allocator, "s3.dualstack.us-east-1.amazonaws.com");
    const struct aws_string *host_name_2 = aws_string_from_c_str_new(allocator, "s3.us-east-1.amazonaws.com");

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
    };

    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name_1, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    struct aws_host_address host_1_original_ipv6_resolve;
    aws_host_address_copy(&callback_data.aaaa_address, &host_1_original_ipv6_resolve);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name_2, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    struct aws_host_address host_2_original_ipv4_resolve;
    aws_host_address_copy(&callback_data.a_address, &host_2_original_ipv4_resolve);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name_1, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_BIN_ARRAYS_EQUALS(aws_string_bytes(host_1_original_ipv6_resolve.address), host_1_original_ipv6_resolve.address->len,
                             aws_string_bytes(callback_data.aaaa_address.address), callback_data.aaaa_address.address->len);

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name_2, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_BIN_ARRAYS_EQUALS(aws_string_bytes(host_2_original_ipv4_resolve.address), host_2_original_ipv4_resolve.address->len,
                             aws_string_bytes(callback_data.a_address.address), callback_data.a_address.address->len);
    aws_host_address_clean_up(&callback_data.a_address);

    aws_host_address_clean_up(&host_1_original_ipv6_resolve);
    aws_host_address_clean_up(&host_2_original_ipv4_resolve);

    aws_string_destroy((void *)host_name_1);
    aws_string_destroy((void *)host_name_2);
    aws_host_resolver_clean_up(&resolver);

    return 0;
}

AWS_TEST_CASE(test_default_with_multiple_lookups, test_default_with_multiple_lookups_fn)

static int test_resolver_ttls_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_host_resolver resolver;

    ASSERT_SUCCESS(aws_host_resolver_default_init(&resolver, allocator, 10));

    const struct aws_string *host_name = aws_string_from_c_str_new(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_from_c_str_new(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_from_c_str_new(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_from_c_str_new(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_from_c_str_new(allocator, "address2ipv6");


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
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_A,
            .use_count = 0,
            .weight = 0
    };

    struct aws_host_address host_address_1_ipv6 = {
            .address = addr1_ipv6,
            .allocator = allocator,
            .expiry = 0,
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
            .use_count = 0,
            .weight = 0
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
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_A,
            .use_count = 0,
            .weight = 0
    };

    struct aws_host_address host_address_2_ipv6 = {
            .address = addr2_ipv6,
            .allocator = allocator,
            .expiry = 0,
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
            .use_count = 0,
            .weight = 0
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
    };

    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    ASSERT_TRUE(aws_string_eq(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);
    /* sleep one second, as a result the next resolve should run.*/
    aws_thread_current_sleep(1500000000);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    ASSERT_TRUE(aws_string_eq(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* sleep one second, as a result the next resolve should run.*/
    aws_thread_current_sleep(1500000000);

    /* note that normally, the first address would come back, but the TTL is expired (we set it to one second).
     * As a result, we should get the second one again.*/

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_TRUE(aws_string_eq(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* sleep so entry two expires. Now everything is expired, but because the last thing we resolved was addr 2, it should still be there. */
    aws_thread_current_sleep(1500000000);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_TRUE(aws_string_eq(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr2_ipv4, callback_data.a_address.address));
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);


    mock_dns_resolver_clean_up(&mock_resolver);
    aws_string_destroy((void *)host_name);
    aws_host_resolver_clean_up(&resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_ttls, test_resolver_ttls_fn)

static int test_resolver_connect_failure_recording_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_host_resolver resolver;

    ASSERT_SUCCESS(aws_host_resolver_default_init(&resolver, allocator, 10));

    const struct aws_string *host_name = aws_string_from_c_str_new(allocator, "host_address");

    const struct aws_string *addr1_ipv4 = aws_string_from_c_str_new(allocator, "address1ipv4");
    const struct aws_string *addr1_ipv6 = aws_string_from_c_str_new(allocator, "address1ipv6");

    const struct aws_string *addr2_ipv4 = aws_string_from_c_str_new(allocator, "address2ipv4");
    const struct aws_string *addr2_ipv6 = aws_string_from_c_str_new(allocator, "address2ipv6");


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
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_A,
            .use_count = 0,
            .weight = 0
    };

    struct aws_host_address host_address_1_ipv6 = {
            .address = addr1_ipv6,
            .allocator = allocator,
            .expiry = 0,
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
            .use_count = 0,
            .weight = 0
    };

    struct aws_host_address host_address_2_ipv4 = {
            .address = addr2_ipv4,
            .allocator = allocator,
            .expiry = 0,
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_A,
            .use_count = 0,
            .weight = 0
    };

    struct aws_host_address host_address_2_ipv6 = {
            .address = addr2_ipv6,
            .allocator = allocator,
            .expiry = 0,
            .host = host_name,
            .connection_failure_count = 0,
            .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
            .use_count = 0,
            .weight = 0
    };

    struct aws_array_list address_list_1;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list_1, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_2_ipv4));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list_1, &host_address_1_ipv4));

    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_resolver, &address_list_1));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct default_host_callback_data callback_data = {
            .condition_variable = AWS_CONDITION_VARIABLE_INIT,
            .invoked = false,
            .has_aaaa_address = false,
            .has_a_address = false,
    };

    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    ASSERT_TRUE(aws_string_eq(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr1_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    ASSERT_TRUE(aws_string_eq(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(&resolver, &host_address_1_ipv6));
    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(&resolver, &host_address_1_ipv4));

    /* following the LRU policy, address 1 should be what gets returned here, however we marked it as failed, so it should
     * be skipped and address 2 should be returned. */
    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_TRUE(aws_string_eq(addr2_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr2_ipv4, callback_data.a_address.address));

    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(&resolver, &host_address_2_ipv6));
    ASSERT_SUCCESS(aws_host_resolver_record_connection_failure(&resolver, &host_address_2_ipv4));

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    /* here address 1 should be returned since it is now the least recently used address and all of them have failed.. */
    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_TRUE(aws_string_eq(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr1_ipv4, callback_data.a_address.address));
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    /* let it re-resolve, and we should still have the other connections marked as connection failures. */
    aws_thread_current_sleep(1500000000);

    callback_data.invoked = false;
    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    /* here address 1 should still be the one returned because though we re-resolved, we don't trust the dns entries yet
     * and we kept them as bad addresses. */
    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);
    ASSERT_TRUE(aws_string_eq(addr1_ipv6, callback_data.aaaa_address.address));
    ASSERT_TRUE(aws_string_eq(addr1_ipv4, callback_data.a_address.address));
    aws_host_address_clean_up(&callback_data.aaaa_address);
    aws_host_address_clean_up(&callback_data.a_address);

    mock_dns_resolver_clean_up(&mock_resolver);
    aws_string_destroy((void *)host_name);
    aws_host_resolver_clean_up(&resolver);

    return 0;
}

AWS_TEST_CASE(test_resolver_connect_failure_recording, test_resolver_connect_failure_recording_fn)



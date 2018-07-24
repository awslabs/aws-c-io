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
#include <aws/io/host_resolver.h>
#include <aws/common/condition_variable.h>
#include <inttypes.h>

struct default_host_callback_data {
    struct aws_host_address aaaa_address;
    struct aws_host_address a_address;
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
    aws_array_list_get_at(host_addresses, &host_address, 0);

    aws_host_address_copy(host_address, &callback_data->aaaa_address);

    aws_array_list_get_at(host_addresses, &host_address, 1);

    aws_host_address_copy(host_address, &callback_data->a_address);
    uint64_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);
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
    };

    ASSERT_SUCCESS(
            aws_host_resolver_resolve_host(&resolver, host_name, default_host_resolved_test_callback, &config,
                                           &callback_data));

    aws_condition_variable_wait_pred(&callback_data.condition_variable, &mutex, default_host_resolved_predicate, &callback_data);

    callback_data.invoked = false;
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_AAAA, callback_data.aaaa_address.record_type);
    ASSERT_BIN_ARRAYS_EQUALS(aws_string_bytes(host_name), host_name->len,
                             aws_string_bytes(callback_data.aaaa_address.host),
                             callback_data.aaaa_address.host->len);
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
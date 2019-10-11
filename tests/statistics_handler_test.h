#ifndef STATISTICS_HANDLER_TEST_H
#define STATISTICS_HANDLER_TEST_H

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

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/statistics.h>

struct aws_statistics_handler_test_impl {
    uint64_t start_time_ns;

    uint64_t total_bytes_read;
    uint64_t total_bytes_written;

    enum aws_tls_negotiation_status tls_status;

    struct aws_mutex lock;
    struct aws_condition_variable signal;
};

struct aws_crt_statistics_handler *aws_statistics_handler_new_test(struct aws_allocator *allocator);

#endif // STATISTICS_HANDLER_TEST_H
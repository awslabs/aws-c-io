#ifndef STATISTICS_HANDLER_TEST_H
#define STATISTICS_HANDLER_TEST_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
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

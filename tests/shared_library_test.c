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

#include <aws/io/shared_library.h>

#include <aws/testing/aws_test_harness.h>

#ifdef _WIN32
static const char *s_self_path = "..\\aws-c-io.dll";
#else
static const char *s_self_path = "../libaws-c-io.so";
#endif

static int s_shared_library_open_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    struct aws_shared_library library;
    ASSERT_FAILS(aws_shared_library_init(&library, "not-a-real-library.blah"));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(shared_library_open_failure, s_shared_library_open_failure);

static int s_shared_library_open_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    struct aws_shared_library library;
    ASSERT_SUCCESS(aws_shared_library_init(&library, s_self_path));

    aws_shared_library_clean_up(&library);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(shared_library_open_success, s_shared_library_open_success);

static int s_shared_library_find_symbol_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    struct aws_shared_library library;
    ASSERT_SUCCESS(aws_shared_library_init(&library, s_self_path));

    void *find_symbol = NULL;
    ASSERT_SUCCESS(aws_shared_library_get_symbol(&library, "aws_shared_library_get_symbol", &find_symbol));

    int (*find_symbol_fn)(struct aws_shared_library *, const char *, void **) = find_symbol;
    ASSERT_TRUE(find_symbol_fn == aws_shared_library_get_symbol);

    aws_shared_library_clean_up(&library);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(shared_library_find_symbol_success, s_shared_library_find_symbol_success);

static int s_shared_library_find_symbol_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    struct aws_shared_library library;
    ASSERT_SUCCESS(aws_shared_library_init(&library, s_self_path));

    void *find_symbol = NULL;
    ASSERT_FAILS(aws_shared_library_get_symbol(&library, "not_a_real_function", &find_symbol));
    ASSERT_TRUE(find_symbol == NULL);

    aws_shared_library_clean_up(&library);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(shared_library_find_symbol_failure, s_shared_library_find_symbol_failure);
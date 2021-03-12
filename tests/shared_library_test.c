/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/shared_library.h>

#include <aws/testing/aws_test_harness.h>

#ifdef _WIN32
/*
 * We may need to monkey with paths (or copy .dlls) a bit when we create shared library builds
 */
static const char *s_self_path = ".\\aws-c-io.dll";
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

typedef int (*find_symbol_function)(struct aws_shared_library *, const char *, aws_generic_function *);

static int s_shared_library_find_function_success(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    struct aws_shared_library library;
    ASSERT_SUCCESS(aws_shared_library_init(&library, s_self_path));

    aws_generic_function find_symbol = NULL;
    ASSERT_SUCCESS(aws_shared_library_find_function(&library, "aws_shared_library_find_function", &find_symbol));

    find_symbol_function find = (find_symbol_function)find_symbol;
    ASSERT_TRUE(find != NULL);

    aws_shared_library_clean_up(&library);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(shared_library_find_function_success, s_shared_library_find_function_success);

static int s_shared_library_find_function_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

    struct aws_shared_library library;
    ASSERT_SUCCESS(aws_shared_library_init(&library, s_self_path));

    aws_generic_function find_symbol = NULL;
    ASSERT_FAILS(aws_shared_library_find_function(&library, "not_a_real_function", &find_symbol));
    ASSERT_TRUE(find_symbol == NULL);

    aws_shared_library_clean_up(&library);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(shared_library_find_function_failure, s_shared_library_find_function_failure);


#ifndef AWS_FUTURE_TEST_H
#define AWS_FUTURE_TEST_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/future.h>

struct aws_destroyme *aws_destroyme_new(struct aws_allocator *alloc, bool *set_true_on_death);
void aws_destroyme_destroy(struct aws_destroyme *destroyme);

/* We get unused-function warnings if this macro is used in a .c file, so put it in a header */
AWS_DECLARE_FUTURE_T_POINTER_WITH_DESTROY(aws_future_destroyme, struct aws_destroyme, aws_destroyme_destroy);

struct aws_refcountme *aws_refcountme_new(struct aws_allocator *alloc, bool *set_true_on_death);
struct aws_refcountme *aws_refcountme_acquire(struct aws_refcountme *refcountme);
struct aws_refcountme *aws_refcountme_release(struct aws_refcountme *refcountme);
AWS_DECLARE_FUTURE_T_POINTER_WITH_RELEASE(aws_future_refcountme, struct aws_refcountme, aws_refcountme_release);

#endif /* AWS_FUTURE_TEST_H */

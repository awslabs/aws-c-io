#ifndef AWS_IO_PEM_UTILS_H
#define AWS_IO_PEM_UTILS_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>

AWS_EXTERN_C_BEGIN

/**
 * Cleanup Function that parses the full PEM Chain one object at a time and rewrites it following the
 * RFC formatting rules. Only well formatted pem file will be accepted.
 *
 * Performs the following operations and fixes:
 * - Garbage characters in-between PEM objects (characters before the first BEGIN or after an END and before the next
 * BEGIN) are removed
 */
AWS_IO_API
struct aws_string *aws_clean_up_pem(struct aws_byte_cursor pem, struct aws_allocator *allocator);

AWS_EXTERN_C_END
#endif /* AWS_IO_PEM_UTILS_H */

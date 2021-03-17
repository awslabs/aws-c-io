#ifndef AWS_IO_PEM_UTILS_H
#define AWS_IO_PEM_UTILS_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>

AWS_EXTERN_C_BEGIN

/**
 * Cleanup Function that parses the full PEM Chain object once and strip the comments out for the pem parser not
 * handling the comments. Create a new aws_byte_buf.
 *
 * - Garbage characters in-between PEM objects (characters before the first BEGIN or after an END and before the next
 * BEGIN) are removed
 */
AWS_IO_API
struct aws_byte_buf aws_clean_up_pem(struct aws_byte_cursor pem, struct aws_allocator *allocator);

AWS_EXTERN_C_END
#endif /* AWS_IO_PEM_UTILS_H */

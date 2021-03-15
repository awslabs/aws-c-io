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
 * RFC formatting rules.
 *
 * Performs the following operations and fixes:
 * - Garbage characters in-between PEM objects (characters before the first BEGIN or after an END and before the next
 * BEGIN) are removed
 * - The number of dashes "-" on the BEGIN and END lines are exactly 5 dashes
 * - Only whitespace is a single newline every 64 chars
 * - All lines exactly 64 Characters long except for the last line.
 * - Remove any invalid character.
 * - Merge consecutive spaces into a single space (Eg "BEGIN     CERTIFICATE", will become "BEGIN CERTIFICATE")
 * - Remove any spaces next to dashes (Eg "----- BEGIN" will become "-----BEGIN")
 *
 * Note: Newline is required to the end of PEM headers, otherwise will be considered as invalid pem.
 */
AWS_IO_API
struct aws_string *aws_clean_up_pem(struct aws_byte_cursor pem, struct aws_allocator *allocator);

AWS_EXTERN_C_END
#endif /* AWS_IO_PEM_UTILS_H */

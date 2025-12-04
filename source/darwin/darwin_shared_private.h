#ifndef AWS_IO_DARWIN_SHARED_PRIVATE_H
#define AWS_IO_DARWIN_SHARED_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <CoreFoundation/CoreFoundation.h>

void aws_get_core_foundation_error_description(CFErrorRef error, char *description_buffer, size_t buffer_size);

#endif // AWS_IO_DARWIN_SHARED_PRIVATE_H

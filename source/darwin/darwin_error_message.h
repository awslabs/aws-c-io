#ifndef AWS_DARWIN_ERROR_MESSAGE_H
#define AWS_DARWIN_ERROR_MESSAGE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <aws/io/logging.h>

void aws_darwin_log_message(
    enum aws_log_level log_level,
    aws_log_subject_t subject,
    const char *function_name,
    OSStatus status);

#endif /* AWS_DARWIN_ERROR_MESSAGE_H */

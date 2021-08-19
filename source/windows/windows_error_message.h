#ifndef AWS_WINDOWS_ERROR_MESSAGE_H
#define AWS_WINDOWS_ERROR_MESSAGE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <Windows.h>

int aws_win_format_message(LPTSTR buffer, size_t buffer_size, DWORD lastError) {
    return FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, lastError, 0, buffer, buffer_size, NULL);
}

#endif /* AWS_WINDOWS_ERROR_MESSAGE_H */

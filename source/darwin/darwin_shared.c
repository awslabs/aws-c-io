/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "darwin_shared_private.h"

/*
 * Helper function that gets the available human-readable error description from Core Foundation.
 */
void aws_get_core_foundation_error_description(CFErrorRef error, char *description_buffer, size_t buffer_size) {
    if (error == NULL) {
        snprintf(description_buffer, buffer_size, "No error provided");
        return;
    }

    CFStringRef error_description = CFErrorCopyDescription(error);
    if (error_description) {
        CFStringGetCString(error_description, description_buffer, buffer_size, kCFStringEncodingUTF8);
        CFRelease(error_description);
    } else {
        snprintf(description_buffer, buffer_size, "Unable to retrieve error description");
    }
}

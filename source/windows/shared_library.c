/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/* In theory clang-format doesn't get run on this, but someday maybe it will*/
/* clang-format off */
#include <Windows.h>
#include <libloaderapi.h>
/* clang-format on */

#include <aws/io/shared_library.h>

#include <aws/io/logging.h>

static const char *s_null = "<NULL>";
static const char *s_unknown_error = "<Unknown>";

int aws_shared_library_init(struct aws_shared_library *library, const char *library_path) {
    AWS_ZERO_STRUCT(*library);

    library->library_handle = LoadLibrary(library_path);
    if (library->library_handle == NULL) {
        DWORD ec = GetLastError();

        AWS_LOGF_ERROR(
            AWS_LS_IO_SHARED_LIBRARY,
            "id=%p: Failed to load shared library at path \"%s\" with Windows error code: %ul",
            (void *)library,
            library_path ? library_path : s_null,
            ec);
        return aws_raise_error(AWS_IO_SHARED_LIBRARY_LOAD_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

void aws_shared_library_clean_up(struct aws_shared_library *library) {
    if (library && library->library_handle) {
        FreeLibrary((HMODULE)library->library_handle);
        library->library_handle = NULL;
    }
}

int aws_shared_library_find_function(
    struct aws_shared_library *library,
    const char *symbol_name,
    aws_generic_function *function_address) {
    if (library == NULL || library->library_handle == NULL) {
        return aws_raise_error(AWS_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE);
    }

    *function_address = (aws_generic_function)GetProcAddress((HMODULE)library->library_handle, symbol_name);
    if (*function_address == NULL) {
        DWORD ec = GetLastError();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SHARED_LIBRARY,
            "id=%p: Failed to find shared library symbol \"%s\" with error code: %ul",
            (void *)library,
            symbol_name ? symbol_name : s_null,
            ec);
        return aws_raise_error(AWS_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

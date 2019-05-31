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

#include <aws/common/shared_library.h>

#include <dlfcn.h>

int aws_shared_library_init(struct aws_shared_library *library, const char *library_path) {
    (void)library;
    (void)library_path;

    library->library_handle = dlopen(library_path, RTLD_LAZY);
    if (library->library_handle == NULL) {
        return aws_raise_error();
    }

    return AWS_OP_SUCCESS;
}

void aws_shared_library_cleanup(struct aws_shared_library *library) {
    (void)library;
}

int aws_shared_library_get_symbol(struct aws_shared_library *library, const char *symbol_name) {
    (void)library;
    (void)symbol_name;

    return AWS_OP_ERR;
}
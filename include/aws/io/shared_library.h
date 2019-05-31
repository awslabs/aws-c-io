#ifndef AWS_COMMON_SHARED_LIBRARY_H
#define AWS_COMMON_SHARED_LIBRARY_H

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

#include <aws/common/common.h>

struct aws_byte_cursor;

struct aws_shared_library {
    void *library_handle;
};

AWS_EXTERN_C_BEGIN

AWS_COMMON_API
int aws_shared_library_init(struct aws_shared_library *library, const char *library_path);

AWS_COMMON_API
void aws_shared_library_cleanup(struct aws_shared_library *library);

AWS_COMMON_API
int aws_shared_library_get_symbol(struct aws_shared_library *library, const char *symbol_name);

AWS_EXTERN_C_END

#endif //AWS_COMMON_SHARED_LIBRARY_H

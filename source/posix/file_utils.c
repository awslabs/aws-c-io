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

#include <aws/io/file_utils.h>

char aws_get_local_platform_directory_separator(void) {
    return '/';
}

struct aws_string *aws_get_home_directory(struct aws_allocator *allocator) {

    /* ToDo: check getpwuid_r if environment check fails */
    return aws_get_home_directory_environment_value(allocator);
}

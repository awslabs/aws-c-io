#ifndef AWS_IO_URI_H
#define AWS_IO_URI_H
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
#include <aws/common/byte_buf.h>

#include <aws/io/exports.h>

struct aws_uri {
    struct aws_allocator *allocator;
    struct aws_byte_buf uri_str;
    struct aws_byte_cursor scheme;
    struct aws_byte_cursor authority;
    struct aws_byte_cursor path;
    struct aws_byte_cursor query_string;
};

AWS_EXTERN_C_BEGIN

int aws_uri_init_parse(struct aws_uri *uri, struct aws_allocator *allocator, const struct aws_byte_cursor *uri_str);
int aws_uri_init(struct aws_uri *uri, struct aws_allocator *allocator);
void aws_uri_clean_up(struct aws_uri *uri);

const struct aws_byte_cursor *aws_uri_scheme(const struct aws_uri *uri);
const struct aws_byte_cursor *aws_uri_authority(const struct aws_uri *uri);
const struct aws_byte_cursor *aws_uri_path(const struct aws_uri *uri);
const struct aws_byte_cursor *aws_uri_query_string(const struct aws_uri *uri);

AWS_EXTERN_C_END

#endif /* AWS_IO_URI_H */

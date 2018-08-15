#ifndef AWS_IO_FILE_UTILS_H
#define AWS_IO_FILE_UTILS_H
/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/io/io.h>

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_read_file_to_buffer(struct aws_allocator *alloc, const char *filename,
                                       struct aws_byte_buf *out_buf);

AWS_IO_API void aws_cert_chain_clean_up(struct aws_array_list *cert_chain);

AWS_IO_API int aws_decode_pem_to_buffer_list(struct aws_allocator *alloc,
                                            const struct aws_byte_buf *pem_buffer,
                                            struct aws_array_list *cert_chain_or_key);

AWS_IO_API int aws_read_and_decode_pem_file_to_buffer_list(struct aws_allocator *alloc,
                                                           const char *filename,
                                                           struct aws_array_list *cert_chain_or_key);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_FILE_UTILS_H */
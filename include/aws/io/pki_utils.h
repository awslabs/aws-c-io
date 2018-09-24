#ifndef AWS_IO_PKI_UTILS_H
#define AWS_IO_PKI_UTILS_H
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

/**
 * Reads 'filename' into 'out_buf'. If successful, 'out_buf' is allocated and filled with the data;
 * It is your responsibility to call 'aws_byte_buf_clean_up()' on it. Otherwise, 'out_buf' remains
 * unused. In the very unfortunate case where some API needs to treat out_buf as a c_string, a null terminator
 * is appended, but is not included as part of the length field.
 */
AWS_IO_API int aws_byte_buf_init_from_file(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *alloc,
    const char *filename);

/**
 * Cleans up and securely zeroes out the outputs of 'aws_decode_pem_to_buffer_list()'
 * and 'aws_read_and_decode_pem_file_to_buffer_list()'
 */
AWS_IO_API void aws_cert_chain_clean_up(struct aws_array_list *cert_chain);

/**
 * Decodes a PEM file and adds the results to 'cert_chain_or_key' if successful.
 * Otherwise, 'cert_chain_or_key' will be empty. The type stored in 'cert_chain_or_key'
 * is 'struct aws_byte_buf' by value. This code is slow, and it allocates, so please try
 * not to call this in the middle of something that needs to be fast or resource sensitive.
 */
AWS_IO_API int aws_decode_pem_to_buffer_list(
    struct aws_allocator *alloc,
    const struct aws_byte_buf *pem_buffer,
    struct aws_array_list *cert_chain_or_key);

/**
 * Decodes a PEM file at 'filename' and adds the results to 'cert_chain_or_key' if successful.
 * Otherwise, 'cert_chain_or_key' will be empty. The type stored in 'cert_chain_or_key'
 * is 'struct aws_byte_buf' by value. This code is slow, and it allocates, so please try
 * not to call this in the middle of something that needs to be fast or resource sensitive.
 */
AWS_IO_API int aws_read_and_decode_pem_file_to_buffer_list(
    struct aws_allocator *alloc,
    const char *filename,
    struct aws_array_list *cert_chain_or_key);

#ifdef __MACH__
#include <CoreFoundation/CoreFoundation.h>

int aws_import_public_and_private_keys_to_identity(struct aws_allocator* alloc, CFAllocatorRef cf_alloc,
                                                   struct aws_byte_buf* public_cert_chain, struct aws_byte_buf* private_key, CFArrayRef *identity);

int aws_import_pkcs12_to_identity(CFAllocatorRef cf_alloc, struct aws_byte_buf* pkcs12_buffer, struct aws_byte_buf* password, CFArrayRef *identity);

int aws_import_trusted_certificates(struct aws_allocator *alloc, CFAllocatorRef cf_alloc, struct aws_byte_buf *certificates_blob, CFArrayRef *certs);

void aws_release_identity(CFArrayRef identity);

void aws_release_certificates(CFArrayRef certs);


#endif /* __MACH__ */
/*
#ifdef _WIN32
AWS_IO_API int aws_open_ephemeral_cert_store(struct aws_allocator *alloc, HCERTSTORE *cert_store);
AWS_IO_API int aws_open_system_cert_store(struct aws_allocator *alloc, int registry_location, HCERTSTORE *cert_store);
AWS_IO_API int aws_open_cert_store_from_file(struct aws_allocator *alloc, const char *file_name, HCERTSTORE *cert_store);
AWS_IO_API void aws_close_cert_store(HCERTSTORE cert_store);
AWS_IO_API int aws_import_key_pair_to_store(HCERTSTORE cert_store, struct aws_allocator *alloc, 
    struct aws_byte_buf *public_cert_chain, struct aws_byte_buf *private_key, PCCERT_CONTEXT *certs);
#endif*/ /* _WIN32 */

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_PKI_UTILS_H */

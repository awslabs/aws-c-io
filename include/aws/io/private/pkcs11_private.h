#ifndef AWS_IO_PKCS11_PRIVATE_H
#define AWS_IO_PKCS11_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>
#include <s2n.h>

/* These defines must exist before the official PKCS#11 headers are included */
#define CK_PTR *
#define NULL_PTR 0
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(CK_PTR name)
#include <aws/io/private/pkcs11/v2.40/pkcs11.h>

/* clang-format off */
/*
 * DER encoded DigestInfo value for SHA to be prefixed to the hash, used for RSA signing
 * See https://tools.ietf.org/html/rfc3447#page-43
 */
#define pkcs11SHA1_PREFIX_TO_RSA_SIG { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 }
#define pkcs11SHA256_PREFIX_TO_RSA_SIG { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }
#define pkcs11SHA384_PREFIX_TO_RSA_SIG { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 }
#define pkcs11SHA512_PREFIX_TO_RSA_SIG { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 }
#define pkcs11SHA224_PREFIX_TO_RSA_SIG { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c }
/* clang-format on */

struct aws_pkcs11_lib;
struct aws_string;

/**
 * pkcs11_private.h
 * This file declares symbols that are private to aws-c-io but need to be
 * accessed from multiple .c files.
 */

AWS_EXTERN_C_BEGIN

/**
 * Return c-string for PKCS#11 CKR_* constant.
 * For use in tests only.
 */
AWS_IO_API
const char *aws_pkcs11_ckr_str(CK_RV rv);

/**
 * Return the raw function list.
 * For use in tests only.
 */
AWS_IO_API
CK_FUNCTION_LIST *aws_pkcs11_lib_get_function_list(struct aws_pkcs11_lib *pkcs11_lib);

/**
 * Find the slot that meets all criteria:
 * - has a token
 * - if match_slot_id is non-null, then slot IDs must match
 * - if match_token_label is non-null, then labels must match
 * The function fails unless it finds exactly one slot meeting all criteria.
 */
AWS_IO_API
int aws_pkcs11_lib_find_slot_with_token(
    struct aws_pkcs11_lib *pkcs11_lib,
    const uint64_t *match_slot_id,
    const struct aws_string *match_token_label,
    CK_SLOT_ID *out_slot_id);

AWS_IO_API
int aws_pkcs11_lib_open_session(
    struct aws_pkcs11_lib *pkcs11_lib,
    CK_SLOT_ID slot_id,
    CK_SESSION_HANDLE *out_session_handle);

AWS_IO_API
void aws_pkcs11_lib_close_session(struct aws_pkcs11_lib *pkcs11_lib, CK_SESSION_HANDLE session_handle);

AWS_IO_API
int aws_pkcs11_lib_login_user(
    struct aws_pkcs11_lib *pkcs11_lib,
    CK_SESSION_HANDLE session_handle,
    const struct aws_string *optional_user_pin);

/**
 * Find the object that meets all criteria:
 * - is private key
 * - if match_label is non-null, then labels must match
 * The function fails unless it finds exactly one object meeting all criteria.
 */
AWS_IO_API
int aws_pkcs11_lib_find_private_key(
    struct aws_pkcs11_lib *pkcs11_lib,
    CK_SESSION_HANDLE session_handle,
    const struct aws_string *match_label,
    CK_OBJECT_HANDLE *out_key_handle,
    CK_KEY_TYPE *out_key_type);

/**
 * Decrypt the encrypted data.
 * out_data should be passed in uninitialized.
 * If successful, out_data will be initialized and contain the recovered data.
 */
AWS_IO_API
int aws_pkcs11_lib_decrypt(
    struct aws_pkcs11_lib *pkcs11_lib,
    CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle,
    CK_KEY_TYPE key_type,
    struct aws_byte_cursor encrypted_data,
    struct aws_allocator *allocator,
    struct aws_byte_buf *out_data);

/**
 * Sign the data.
 * out_signature should be passed in uninitialized.
 * If successful, out_signature will be initialized and contain the signature.
 */
AWS_IO_API
int aws_pkcs11_lib_sign(
    struct aws_pkcs11_lib *pkcs11_lib,
    CK_SESSION_HANDLE session_handle,
    CK_OBJECT_HANDLE key_handle,
    CK_KEY_TYPE key_type,
    struct aws_byte_cursor input_data,
    struct aws_allocator *allocator,
    s2n_tls_hash_algorithm digest_alg,
    struct aws_byte_buf *out_signature);

AWS_EXTERN_C_END
#endif /* AWS_IO_PKCS11_PRIVATE_H */

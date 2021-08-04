#ifndef AWS_IO_PKCS11_H
#define AWS_IO_PKCS11_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>

struct aws_allocator;

/**
 * Handle to a loaded PKCS#11 library.
 */
struct aws_pkcs11_lib_handle;

/**
 * Options for aws_pkcs11_lib_handle_new()
 */
struct aws_pkcs11_lib_handle_options {
    /**
     * Name of PKCS#11 library file to load (UTF-8).
     * Set to empty if your application is compiled with PKCS#11 symbols linked in.
     */
    struct aws_byte_cursor filename;

    /**
     * Set true to skip calling C_Initialize() and C_Finalize() on the PKCS#11 library.
     * Use this only if your application has already initialized the PKCS#11 library.
     */
    bool omit_initialize;
};

AWS_EXTERN_C_BEGIN

/**
 * Load and initialize a PKCS#11 library.
 * See `aws_pkcs11_lib_handle_new_options` for options.
 *
 * If successful a handle is returned. You must call aws_pkcs11_lib_handle_release() when you are done with it.
 * If unsuccessful, NULL is returned and an error is set.
 */
AWS_IO_API
struct aws_pkcs11_lib_handle *aws_pkcs11_lib_handle_new(
    struct aws_allocator *allocator,
    const struct aws_pkcs11_lib_handle_options *options);

/**
 * Acquire a reference to a PKCS#11 library handle, preventing it from being cleaned up.
 * You must call aws_pkcs11_lib_handle_release() when you are done with it.
 * This function returns whatever was passed in. It cannot fail.
 */
AWS_IO_API
struct aws_pkcs11_lib_handle *aws_pkcs11_lib_handle_acquire(struct aws_pkcs11_lib_handle *pkcs11_lib);

/**
 * Release a reference to the PKCS#11 library handle.
 * When the last reference is released, the library is cleaned up.
 */
AWS_IO_API
void aws_pkcs11_lib_handle_release(struct aws_pkcs11_lib_handle *pkcs11_lib);

AWS_EXTERN_C_END

#endif /* AWS_IO_PKCS11_H */

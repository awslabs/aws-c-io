/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/pkcs11.h>

#include "pkcs11_private.h"

#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>

struct aws_pkcs11_tls_op_handler {
    /* The custom key operation handler needed for the callbacks */
    struct aws_custom_key_op_handler base;

    struct aws_allocator *alloc;
    struct aws_pkcs11_lib *lib;

    /* Use a single PKCS#11 session for all TLS connections on an aws_tls_ctx.
     * We do this because PKCS#11 tokens may only support a
     * limited number of sessions (PKCS11-UG-v2.40 section 2.6.7).
     * If this one shared session turns out to be a severe bottleneck,
     * we could look into other setups (ex: put session on its own thread,
     * 1 session per event-loop, 1 session per connection, etc).
     *
     * The lock must be held while performing session operations.
     * Otherwise, it would not be safe for multiple threads to share a
     * session (PKCS11-UG-v2.40 section 2.6.7). The lock isn't needed for
     * setup and teardown though, since we ensure nothing parallel is going
     * on at these times */
    struct aws_mutex session_lock;
    CK_SESSION_HANDLE session_handle;
    CK_OBJECT_HANDLE private_key_handle;
    CK_KEY_TYPE private_key_type;

    /**
     * Certificate's file path on disk (UTF-8).
     * The certificate must be PEM formatted and UTF-8 encoded.
     * Zero out if passing in certificate by some other means (such as file contents).
     * (Can also be zero out if it is unused, like in PKCS11 implementation)
     */
    struct aws_byte_cursor cert_file_path;

    /**
     * Certificate's file contents (UTF-8).
     * The certificate must be PEM formatted and UTF-8 encoded.
     * Zero out if passing in certificate by some other means (such as file path).
     * (Can also be zero out if it is unused, like in PKCS11 implementation)
     */
    struct aws_byte_cursor cert_file_contents;
};

static void s_aws_custom_key_op_handler_destroy(struct aws_custom_key_op_handler *key_op_handler) {

    struct aws_pkcs11_tls_op_handler *handler = (struct aws_pkcs11_tls_op_handler *)key_op_handler->impl;

    if (handler->session_handle != 0) {
        aws_pkcs11_lib_close_session(handler->lib, handler->session_handle);
    }
    aws_mutex_clean_up(&handler->session_lock);
    aws_pkcs11_lib_release(handler->lib);

    aws_mem_release(handler->alloc, handler);
}

static int s_aws_custom_key_op_handler_get_certificate(
    struct aws_custom_key_op_handler *key_op_handler,
    struct aws_byte_buf *certificate_output) {

    struct aws_pkcs11_tls_op_handler *op_handler = (struct aws_pkcs11_tls_op_handler *)key_op_handler->impl;
    AWS_FATAL_ASSERT(op_handler != NULL);

    struct aws_allocator *allocator = op_handler->alloc;

    /* certificate needs to be set, but there are multiple ways to return it */
    if ((op_handler->cert_file_path.ptr != NULL) && (op_handler->cert_file_contents.ptr != NULL)) {
        return AWS_OP_ERR;
    } else if (op_handler->cert_file_path.ptr != NULL) {
        struct aws_string *tmp_string = aws_string_new_from_cursor(allocator, &op_handler->cert_file_path);
        int op = aws_byte_buf_init_from_file(certificate_output, allocator, aws_string_c_str(tmp_string));
        aws_string_destroy(tmp_string);
        if (op != AWS_OP_SUCCESS) {
            return AWS_OP_ERR;
        }
    } else if (op_handler->cert_file_contents.ptr != NULL) {
        if (aws_byte_buf_init_copy_from_cursor(certificate_output, allocator, op_handler->cert_file_contents)) {
            return AWS_OP_ERR;
        }
    } else {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/**
 * Performs the PKCS11 TLS private key operation. This is called automatically when performing a MQTT TLS handshake.
 */
void s_aws_pkcs11_tls_op_handler_do_operation(
    struct aws_custom_key_op_handler *handler,
    struct aws_tls_key_operation *operation) {

    struct aws_pkcs11_tls_op_handler *pkcs11_handler = (struct aws_pkcs11_tls_op_handler *)handler->impl;
    struct aws_byte_buf output_buf; /* initialized later */
    AWS_ZERO_STRUCT(output_buf);

    /*********** BEGIN CRITICAL SECTION ***********/
    aws_mutex_lock(&pkcs11_handler->session_lock);
    bool success_while_locked = false;

    switch (aws_tls_key_operation_get_type(operation)) {
        case AWS_TLS_KEY_OPERATION_DECRYPT:
            if (aws_pkcs11_lib_decrypt(
                    pkcs11_handler->lib,
                    pkcs11_handler->session_handle,
                    pkcs11_handler->private_key_handle,
                    pkcs11_handler->private_key_type,
                    aws_tls_key_operation_get_input(operation),
                    pkcs11_handler->alloc,
                    &output_buf)) {

                goto unlock;
            }
            break;

        case AWS_TLS_KEY_OPERATION_SIGN:
            if (aws_pkcs11_lib_sign(
                    pkcs11_handler->lib,
                    pkcs11_handler->session_handle,
                    pkcs11_handler->private_key_handle,
                    pkcs11_handler->private_key_type,
                    aws_tls_key_operation_get_input(operation),
                    pkcs11_handler->alloc,
                    aws_tls_key_operation_get_digest_algorithm(operation),
                    aws_tls_key_operation_get_signature_algorithm(operation),
                    &output_buf)) {

                goto unlock;
            }
            break;

        default:
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKCS11,
                "PKCS11 Handler %p: Unknown TLS key operation with value of %u",
                (void *)handler,
                aws_tls_key_operation_get_type(operation));
            aws_raise_error(AWS_ERROR_INVALID_STATE);
            goto unlock;
    }

    success_while_locked = true;
unlock:
    aws_mutex_unlock(&pkcs11_handler->session_lock);
    /*********** END CRITICAL SECTION ***********/

    if (success_while_locked) {
        aws_tls_key_operation_complete(operation, aws_byte_cursor_from_buf(&output_buf));
    } else {
        aws_tls_key_operation_complete_with_error(operation, aws_last_error());
    }

    aws_byte_buf_clean_up(&output_buf);
}

static struct aws_custom_key_op_handler_vtable s_aws_custom_key_op_handler_vtable = {
    .destroy = s_aws_custom_key_op_handler_destroy,
    .on_key_operation = s_aws_pkcs11_tls_op_handler_do_operation,
    .get_certificate = s_aws_custom_key_op_handler_get_certificate,
};

struct aws_custom_key_op_handler *aws_pkcs11_tls_op_handler_new(
    struct aws_allocator *allocator,
    struct aws_pkcs11_lib *pkcs11_lib,
    const struct aws_string *user_pin,
    const struct aws_string *match_token_label,
    const struct aws_string *match_private_key_label,
    const uint64_t *match_slot_id,
    struct aws_byte_cursor cert_file_path,
    struct aws_byte_cursor cert_file_contents) {

    struct aws_pkcs11_tls_op_handler *pkcs11_handler =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_pkcs11_tls_op_handler));

    aws_ref_count_init(
        &pkcs11_handler->base.ref_count,
        &pkcs11_handler->base,
        (aws_simple_completion_callback *)aws_custom_key_op_handler_perform_destroy);

    pkcs11_handler->base.impl = (void *)pkcs11_handler;
    pkcs11_handler->base.vtable = &s_aws_custom_key_op_handler_vtable;

    pkcs11_handler->alloc = allocator;
    pkcs11_handler->lib = aws_pkcs11_lib_acquire(pkcs11_lib); /* cannot fail */
    aws_mutex_init(&pkcs11_handler->session_lock);

    CK_SLOT_ID slot_id;
    if (aws_pkcs11_lib_find_slot_with_token(pkcs11_handler->lib, match_slot_id, match_token_label, &slot_id /*out*/)) {
        goto error;
    }

    if (aws_pkcs11_lib_open_session(pkcs11_handler->lib, slot_id, &pkcs11_handler->session_handle)) {
        goto error;
    }

    if (aws_pkcs11_lib_login_user(pkcs11_handler->lib, pkcs11_handler->session_handle, user_pin)) {
        goto error;
    }

    if (aws_pkcs11_lib_find_private_key(
            pkcs11_handler->lib,
            pkcs11_handler->session_handle,
            match_private_key_label,
            &pkcs11_handler->private_key_handle /*out*/,
            &pkcs11_handler->private_key_type /*out*/)) {
        goto error;
    }

    pkcs11_handler->cert_file_path = cert_file_path;
    pkcs11_handler->cert_file_contents = cert_file_contents;

    return &pkcs11_handler->base;
error:
    aws_custom_key_op_handler_release(&pkcs11_handler->base);
    return NULL;
}

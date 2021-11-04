/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/pkcs11.h>
#include <aws/io/private/pkcs11_private.h>

#include <aws/common/mutex.h>

struct aws_pkcs11_tls_op_handler {
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
};

struct aws_pkcs11_tls_op_handler *aws_pkcs11_tls_op_handler_new(
    struct aws_allocator *allocator,
    struct aws_pkcs11_lib *pkcs11_lib,
    const struct aws_string *user_pin,
    const struct aws_string *match_token_label,
    const struct aws_string *match_private_key_label,
    const uint64_t *match_slot_id) {

    struct aws_pkcs11_tls_op_handler *pkcs11_handler =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_pkcs11_tls_op_handler));

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

    return pkcs11_handler;
error:
    aws_pkcs11_tls_op_handler_destroy(pkcs11_handler);
    return NULL;
}

void aws_pkcs11_tls_op_handler_destroy(struct aws_pkcs11_tls_op_handler *pkcs11_handler) {
    if (pkcs11_handler == NULL) {
        return;
    }

    if (pkcs11_handler->session_handle != 0) {
        aws_pkcs11_lib_close_session(pkcs11_handler->lib, pkcs11_handler->session_handle);
    }
    aws_mutex_clean_up(&pkcs11_handler->session_lock);
    aws_pkcs11_lib_release(pkcs11_handler->lib);

    aws_mem_release(pkcs11_handler->alloc, pkcs11_handler);
}

void aws_pkcs11_tls_op_handler_do_operation(struct aws_tls_key_operation *operation, void *user_data) {
    struct aws_pkcs11_tls_op_handler *pkcs11_handler = user_data;
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

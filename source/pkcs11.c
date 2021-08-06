/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/private/pkcs11_private.h>

#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>
#include <aws/io/shared_library.h>

#include <inttypes.h>

/* These defines must exist before the official PKCS#11 headers are included */
#define CK_PTR *
#define NULL_PTR 0
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(CK_PTR name)
#include <aws/io/private/pkcs11/v2.40/pkcs11.h>

/* Return c-string for PKCS#11 CKR_* contants */
const char *s_ckr_str(CK_RV rv) {
    /* clang-format off */
    switch (rv) {
        case (CKR_OK): return "CKR_OK";
        case (CKR_CANCEL): return "CKR_CANCEL";
        case (CKR_HOST_MEMORY): return "CKR_HOST_MEMORY";
        case (CKR_SLOT_ID_INVALID): return "CKR_SLOT_ID_INVALID";
        case (CKR_GENERAL_ERROR): return "CKR_GENERAL_ERROR";
        case (CKR_FUNCTION_FAILED): return "CKR_FUNCTION_FAILED";
        case (CKR_ARGUMENTS_BAD): return "CKR_ARGUMENTS_BAD";
        case (CKR_NO_EVENT): return "CKR_NO_EVENT";
        case (CKR_NEED_TO_CREATE_THREADS): return "CKR_NEED_TO_CREATE_THREADS";
        case (CKR_CANT_LOCK): return "CKR_CANT_LOCK";
        case (CKR_ATTRIBUTE_READ_ONLY): return "CKR_ATTRIBUTE_READ_ONLY";
        case (CKR_ATTRIBUTE_SENSITIVE): return "CKR_ATTRIBUTE_SENSITIVE";
        case (CKR_ATTRIBUTE_TYPE_INVALID): return "CKR_ATTRIBUTE_TYPE_INVALID";
        case (CKR_ATTRIBUTE_VALUE_INVALID): return "CKR_ATTRIBUTE_VALUE_INVALID";
        case (CKR_ACTION_PROHIBITED): return "CKR_ACTION_PROHIBITED";
        case (CKR_DATA_INVALID): return "CKR_DATA_INVALID";
        case (CKR_DATA_LEN_RANGE): return "CKR_DATA_LEN_RANGE";
        case (CKR_DEVICE_ERROR): return "CKR_DEVICE_ERROR";
        case (CKR_DEVICE_MEMORY): return "CKR_DEVICE_MEMORY";
        case (CKR_DEVICE_REMOVED): return "CKR_DEVICE_REMOVED";
        case (CKR_ENCRYPTED_DATA_INVALID): return "CKR_ENCRYPTED_DATA_INVALID";
        case (CKR_ENCRYPTED_DATA_LEN_RANGE): return "CKR_ENCRYPTED_DATA_LEN_RANGE";
        case (CKR_FUNCTION_CANCELED): return "CKR_FUNCTION_CANCELED";
        case (CKR_FUNCTION_NOT_PARALLEL): return "CKR_FUNCTION_NOT_PARALLEL";
        case (CKR_FUNCTION_NOT_SUPPORTED): return "CKR_FUNCTION_NOT_SUPPORTED";
        case (CKR_KEY_HANDLE_INVALID): return "CKR_KEY_HANDLE_INVALID";
        case (CKR_KEY_SIZE_RANGE): return "CKR_KEY_SIZE_RANGE";
        case (CKR_KEY_TYPE_INCONSISTENT): return "CKR_KEY_TYPE_INCONSISTENT";
        case (CKR_KEY_NOT_NEEDED): return "CKR_KEY_NOT_NEEDED";
        case (CKR_KEY_CHANGED): return "CKR_KEY_CHANGED";
        case (CKR_KEY_NEEDED): return "CKR_KEY_NEEDED";
        case (CKR_KEY_INDIGESTIBLE): return "CKR_KEY_INDIGESTIBLE";
        case (CKR_KEY_FUNCTION_NOT_PERMITTED): return "CKR_KEY_FUNCTION_NOT_PERMITTED";
        case (CKR_KEY_NOT_WRAPPABLE): return "CKR_KEY_NOT_WRAPPABLE";
        case (CKR_KEY_UNEXTRACTABLE): return "CKR_KEY_UNEXTRACTABLE";
        case (CKR_MECHANISM_INVALID): return "CKR_MECHANISM_INVALID";
        case (CKR_MECHANISM_PARAM_INVALID): return "CKR_MECHANISM_PARAM_INVALID";
        case (CKR_OBJECT_HANDLE_INVALID): return "CKR_OBJECT_HANDLE_INVALID";
        case (CKR_OPERATION_ACTIVE): return "CKR_OPERATION_ACTIVE";
        case (CKR_OPERATION_NOT_INITIALIZED): return "CKR_OPERATION_NOT_INITIALIZED";
        case (CKR_PIN_INCORRECT): return "CKR_PIN_INCORRECT";
        case (CKR_PIN_INVALID): return "CKR_PIN_INVALID";
        case (CKR_PIN_LEN_RANGE): return "CKR_PIN_LEN_RANGE";
        case (CKR_PIN_EXPIRED): return "CKR_PIN_EXPIRED";
        case (CKR_PIN_LOCKED): return "CKR_PIN_LOCKED";
        case (CKR_SESSION_CLOSED): return "CKR_SESSION_CLOSED";
        case (CKR_SESSION_COUNT): return "CKR_SESSION_COUNT";
        case (CKR_SESSION_HANDLE_INVALID): return "CKR_SESSION_HANDLE_INVALID";
        case (CKR_SESSION_PARALLEL_NOT_SUPPORTED): return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
        case (CKR_SESSION_READ_ONLY): return "CKR_SESSION_READ_ONLY";
        case (CKR_SESSION_EXISTS): return "CKR_SESSION_EXISTS";
        case (CKR_SESSION_READ_ONLY_EXISTS): return "CKR_SESSION_READ_ONLY_EXISTS";
        case (CKR_SESSION_READ_WRITE_SO_EXISTS): return "CKR_SESSION_READ_WRITE_SO_EXISTS";
        case (CKR_SIGNATURE_INVALID): return "CKR_SIGNATURE_INVALID";
        case (CKR_SIGNATURE_LEN_RANGE): return "CKR_SIGNATURE_LEN_RANGE";
        case (CKR_TEMPLATE_INCOMPLETE): return "CKR_TEMPLATE_INCOMPLETE";
        case (CKR_TEMPLATE_INCONSISTENT): return "CKR_TEMPLATE_INCONSISTENT";
        case (CKR_TOKEN_NOT_PRESENT): return "CKR_TOKEN_NOT_PRESENT";
        case (CKR_TOKEN_NOT_RECOGNIZED): return "CKR_TOKEN_NOT_RECOGNIZED";
        case (CKR_TOKEN_WRITE_PROTECTED): return "CKR_TOKEN_WRITE_PROTECTED";
        case (CKR_UNWRAPPING_KEY_HANDLE_INVALID): return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
        case (CKR_UNWRAPPING_KEY_SIZE_RANGE): return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
        case (CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT): return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
        case (CKR_USER_ALREADY_LOGGED_IN): return "CKR_USER_ALREADY_LOGGED_IN";
        case (CKR_USER_NOT_LOGGED_IN): return "CKR_USER_NOT_LOGGED_IN";
        case (CKR_USER_PIN_NOT_INITIALIZED): return "CKR_USER_PIN_NOT_INITIALIZED";
        case (CKR_USER_TYPE_INVALID): return "CKR_USER_TYPE_INVALID";
        case (CKR_USER_ANOTHER_ALREADY_LOGGED_IN): return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
        case (CKR_USER_TOO_MANY_TYPES): return "CKR_USER_TOO_MANY_TYPES";
        case (CKR_WRAPPED_KEY_INVALID): return "CKR_WRAPPED_KEY_INVALID";
        case (CKR_WRAPPED_KEY_LEN_RANGE): return "CKR_WRAPPED_KEY_LEN_RANGE";
        case (CKR_WRAPPING_KEY_HANDLE_INVALID): return "CKR_WRAPPING_KEY_HANDLE_INVALID";
        case (CKR_WRAPPING_KEY_SIZE_RANGE): return "CKR_WRAPPING_KEY_SIZE_RANGE";
        case (CKR_WRAPPING_KEY_TYPE_INCONSISTENT): return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
        case (CKR_RANDOM_SEED_NOT_SUPPORTED): return "CKR_RANDOM_SEED_NOT_SUPPORTED";
        case (CKR_RANDOM_NO_RNG): return "CKR_RANDOM_NO_RNG";
        case (CKR_DOMAIN_PARAMS_INVALID): return "CKR_DOMAIN_PARAMS_INVALID";
        case (CKR_CURVE_NOT_SUPPORTED): return "CKR_CURVE_NOT_SUPPORTED";
        case (CKR_BUFFER_TOO_SMALL): return "CKR_BUFFER_TOO_SMALL";
        case (CKR_SAVED_STATE_INVALID): return "CKR_SAVED_STATE_INVALID";
        case (CKR_INFORMATION_SENSITIVE): return "CKR_INFORMATION_SENSITIVE";
        case (CKR_STATE_UNSAVEABLE): return "CKR_STATE_UNSAVEABLE";
        case (CKR_CRYPTOKI_NOT_INITIALIZED): return "CKR_CRYPTOKI_NOT_INITIALIZED";
        case (CKR_CRYPTOKI_ALREADY_INITIALIZED): return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        case (CKR_MUTEX_BAD): return "CKR_MUTEX_BAD";
        case (CKR_MUTEX_NOT_LOCKED): return "CKR_MUTEX_NOT_LOCKED";
        case (CKR_NEW_PIN_MODE): return "CKR_NEW_PIN_MODE";
        case (CKR_NEXT_OTP): return "CKR_NEXT_OTP";
        case (CKR_EXCEEDED_MAX_ITERATIONS): return "CKR_EXCEEDED_MAX_ITERATIONS";
        case (CKR_FIPS_SELF_TEST_FAILED): return "CKR_FIPS_SELF_TEST_FAILED";
        case (CKR_LIBRARY_LOAD_FAILED): return "CKR_LIBRARY_LOAD_FAILED";
        case (CKR_PIN_TOO_WEAK): return "CKR_PIN_TOO_WEAK";
        case (CKR_PUBLIC_KEY_INVALID): return "CKR_PUBLIC_KEY_INVALID";
        case (CKR_FUNCTION_REJECTED): return "CKR_FUNCTION_REJECTED";
        case (CKR_VENDOR_DEFINED): return "CKR_VENDOR_DEFINED";
        default: return "<UNKNOWN ERROR CODE>";
    }
    /* clang-format on */
}

/* Log the failure of a PKCS#11 function, and call aws_raise_error() with the appropriate AWS error code */
static int s_raise_ck_error(const struct aws_pkcs11_lib *pkcs11_lib, const char *fn_name, CK_RV rv) {
    /* For now, we just have one AWS error code for all PKCS#11 errors */
    int aws_err = AWS_IO_PKCS11_ERROR;

    AWS_LOGF_ERROR(
        AWS_LS_IO_PKCS11,
        "id=%p: %s() failed. PKCS#11 error: %s (0x%08lX). AWS error: %s.",
        (void *)pkcs11_lib,
        fn_name,
        s_ckr_str(rv),
        rv,
        aws_error_name(aws_err));

    return aws_raise_error(aws_err);
}

/* PKCS#11 often pads strings with ' ' */
static bool s_is_padding(uint8_t c) {
    return c == ' ';
}

/* Return byte-cursor to string with ' ' padding trimmed off.
 * PKCS#11 structs commonly stores strings in fixed-width arrays, padded by ' ' instead of null-terminator */
static struct aws_byte_cursor s_trim_padding(const uint8_t *str, size_t len) {
    const struct aws_byte_cursor src = aws_byte_cursor_from_array(str, len);
    return aws_byte_cursor_right_trim_pred(&src, s_is_padding);
}

/* Callback for PKCS#11 library to create a mutex.
 * Described in PKCS11-base-v2.40 section 3.7 */
static CK_RV s_pkcs11_create_mutex(CK_VOID_PTR_PTR mutex_out) {
    if (mutex_out == NULL) {
        return CKR_GENERAL_ERROR;
    }

    /* Using the default allocator because there's no way to know which PKCS#11 instance is invoking this callback */
    struct aws_allocator *allocator = aws_default_allocator();

    struct aws_mutex *mutex = aws_mem_calloc(allocator, 1, sizeof(struct aws_mutex));
    if (aws_mutex_init(mutex)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKCS11, "PKCS#11 CreateMutex() failed, error %s", aws_error_name(aws_last_error()));
        aws_mem_release(allocator, mutex);
        *mutex_out = NULL;
        return CKR_GENERAL_ERROR;
    }

    *mutex_out = mutex;
    return CKR_OK;
}

/* Callback for PKCS#11 library to destroy a mutex.
 * Described in PKCS11-base-v2.40 section 3.7 */
static CK_RV s_pkcs11_destroy_mutex(CK_VOID_PTR mutex_ptr) {
    if (mutex_ptr == NULL) {
        return CKR_GENERAL_ERROR;
    }

    struct aws_mutex *mutex = mutex_ptr;
    aws_mutex_clean_up(mutex);
    aws_mem_release(aws_default_allocator(), mutex);
    return CKR_OK;
}

/* Callback for PKCS#11 library to lock a mutex.
 * Described in PKCS11-base-v2.40 section 3.7 */
static CK_RV s_pkcs11_lock_mutex(CK_VOID_PTR mutex_ptr) {
    if (mutex_ptr == NULL) {
        return CKR_GENERAL_ERROR;
    }

    struct aws_mutex *mutex = mutex_ptr;
    if (aws_mutex_lock(mutex)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKCS11, "PKCS#11 LockMutex() failed, error %s", aws_error_name(aws_last_error()));
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

/* Callback for PKCS#11 library to unlock a mutex.
 * Described in PKCS11-base-v2.40 section 3.7 */
static CK_RV s_pkcs11_unlock_mutex(CK_VOID_PTR mutex_ptr) {
    if (mutex_ptr == NULL) {
        return CKR_GENERAL_ERROR;
    }

    struct aws_mutex *mutex = mutex_ptr;
    if (aws_mutex_unlock(mutex)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKCS11, "PKCS#11 LockMutex() failed, error %s", aws_error_name(aws_last_error()));

        /* NOTE: Cryptoki has a CKR_MUTEX_NOT_LOCKED error code.
         * But posix doesn't treat this as an error and neither does windows so ¯\_(ツ)_/¯
         * If aws_mutex_unlock() failed here, it was something else. */
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

struct aws_pkcs11_lib {
    struct aws_ref_count ref_count;
    struct aws_allocator *allocator;

    struct aws_shared_library shared_lib;

    CK_FUNCTION_LIST_PTR function_list;

    /* If true, C_Finalize() should be called when last ref-count is released */
    bool should_finalize;
};

/* Invoked when last ref-count is released. Free all resources.
 * Note that this is also called if initialization fails half-way through */
static void s_pkcs11_lib_destroy(void *user_data) {
    struct aws_pkcs11_lib *pkcs11_lib = user_data;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_PKCS11,
        "id=%p: Unloading PKCS#11. C_Finalize:%s",
        (void *)pkcs11_lib,
        pkcs11_lib->should_finalize ? "yes" : "omit");

    if (pkcs11_lib->should_finalize) {
        CK_RV rv = pkcs11_lib->function_list->C_Finalize(NULL);
        if (rv != CKR_OK) {
            /* Log about it, but continue cleaning up */
            s_raise_ck_error(pkcs11_lib, "C_Finalize", rv);
        }
    }

    aws_shared_library_clean_up(&pkcs11_lib->shared_lib);
    aws_mem_release(pkcs11_lib->allocator, pkcs11_lib);
}

struct aws_pkcs11_lib *aws_pkcs11_lib_new(
    struct aws_allocator *allocator,
    const struct aws_pkcs11_lib_options *options) {

    /* Create the struct */
    struct aws_pkcs11_lib *pkcs11_lib = aws_mem_calloc(allocator, 1, sizeof(struct aws_pkcs11_lib));
    aws_ref_count_init(&pkcs11_lib->ref_count, pkcs11_lib, s_pkcs11_lib_destroy);
    pkcs11_lib->allocator = allocator;

    /* Load the library. */

    /* need a null-terminated string to call next function,
     * or NULL if going to search the current application for PKCS#11 symbols. */
    struct aws_string *filename_storage = NULL;
    const char *filename = NULL;
    if (options->filename.len > 0) {
        filename_storage = aws_string_new_from_cursor(allocator, &options->filename);
        filename = aws_string_c_str(filename_storage);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_PKCS11,
        "Loading PKCS#11. file:'%s' C_Initialize:%s",
        filename ? filename : "<MAIN PROGRAM>",
        options->omit_initialize ? "omit" : "yes");

    if (aws_shared_library_init(&pkcs11_lib->shared_lib, filename)) {
        goto except;
    }

    /* Find C_GetFunctionList() and call it to get the list of pointers to all the other functions */
    CK_C_GetFunctionList get_function_list = NULL;
    if (aws_shared_library_find_function(
            &pkcs11_lib->shared_lib, "C_GetFunctionList", (aws_generic_function *)&get_function_list)) {
        goto except;
    }

    CK_RV rv = get_function_list(&pkcs11_lib->function_list);
    if (rv != CKR_OK) {
        s_raise_ck_error(pkcs11_lib, "C_GetFunctionList", rv);
        goto except;
    }

    /* Call C_Initialize() (skip if omit_initialize is set) */
    if (!options->omit_initialize) {
        CK_C_INITIALIZE_ARGS init_args = {
            /* encourage lib to use our locks */
            .CreateMutex = s_pkcs11_create_mutex,
            .DestroyMutex = s_pkcs11_destroy_mutex,
            .LockMutex = s_pkcs11_lock_mutex,
            .UnlockMutex = s_pkcs11_unlock_mutex,
            /* but if it needs to use OS locks instead, sure whatever you do you */
            .flags = CKF_OS_LOCKING_OK,
        };

        CK_RV rv = pkcs11_lib->function_list->C_Initialize(&init_args);
        if (rv != CKR_OK) {
            s_raise_ck_error(pkcs11_lib, "C_Initialize", rv);
            goto except;
        }

        pkcs11_lib->should_finalize = true;
    }

    /* Get info about the library and log it.
     * This will be VERY useful for diagnosing user issues. */
    CK_INFO info;
    rv = pkcs11_lib->function_list->C_GetInfo(&info);
    if (rv != CKR_OK) {
        s_raise_ck_error(pkcs11_lib, "C_GetInfo", rv);
        goto except;
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_PKCS11,
        "id=%p: PKCS#11 loaded. file:'%s' cryptokiVersion:%" PRIu8 ".%" PRIu8 " manufacturerID:'" PRInSTR
        "' flags:0x%08lX libraryDescription:'" PRInSTR "' libraryVersion:%" PRIu8 ".%" PRIu8 " C_Initialize:%s",
        (void *)pkcs11_lib,
        filename ? filename : "<MAIN PROGRAM>",
        info.cryptokiVersion.major,
        info.cryptokiVersion.minor,
        AWS_BYTE_CURSOR_PRI(s_trim_padding(info.manufacturerID, sizeof(info.manufacturerID))),
        info.flags,
        AWS_BYTE_CURSOR_PRI(s_trim_padding(info.libraryDescription, sizeof(info.libraryDescription))),
        info.libraryVersion.major,
        info.libraryVersion.minor,
        options->omit_initialize ? "omit" : "yes");

    /* Success! */
    goto finally;

except:
    AWS_LOGF_ERROR(
        AWS_LS_IO_PKCS11,
        "id=%p: Failed to initialize PKCS#11 library from '%s'",
        (void *)pkcs11_lib,
        filename ? filename : "<MAIN_PROGRAM>");

    aws_pkcs11_lib_release(pkcs11_lib);
    pkcs11_lib = NULL;

finally:
    aws_string_destroy(filename_storage);
    return pkcs11_lib;
}

struct aws_pkcs11_lib *aws_pkcs11_lib_acquire(struct aws_pkcs11_lib *pkcs11_lib) {
    aws_ref_count_acquire(&pkcs11_lib->ref_count);
    return pkcs11_lib;
}

void aws_pkcs11_lib_release(struct aws_pkcs11_lib *pkcs11_lib) {
    if (pkcs11_lib) {
        aws_ref_count_release(&pkcs11_lib->ref_count);
    }
}

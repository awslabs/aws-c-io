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

/* Support older PKCS#11 versions, even if we're using newer headers.
 * The PKCS#11 API is designed to be forward compatible. */
#include <aws/io/private/pkcs11/v2.40/pkcs11.h>
#define AWS_SUPPORTED_CRYPTOKI_VERSION_MAJOR 2
#define AWS_MIN_SUPPORTED_CRYPTOKI_VERSION_MINOR 20

/* Return c-string for PKCS#11 CKR_* contants. */
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

/* Translate from a CK_RV to an AWS error code */
static int s_ck_to_aws_error(CK_RV rv) {
    /* For now, we just have one AWS error code for all PKCS#11 errors */
    (void)rv;
    return AWS_IO_PKCS11_ERROR;
}

/* Log the failure of a PKCS#11 function, and call aws_raise_error() with the appropriate AWS error code */
static int s_raise_ck_error(const struct aws_pkcs11_lib *pkcs11_lib, const char *fn_name, CK_RV rv) {
    int aws_err = s_ck_to_aws_error(rv);

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

/* Log the failure of a PKCS#11 session-handle function and call aws_raise_error() with the appropriate error code */
static int s_raise_ck_session_error(
    const struct aws_pkcs11_lib *pkcs11_lib,
    const char *fn_name,
    CK_SESSION_HANDLE session,
    CK_RV rv) {

    int aws_err = s_ck_to_aws_error(rv);

    AWS_LOGF_ERROR(
        AWS_LS_IO_PKCS11,
        "id=%p session=%lu: %s() failed. PKCS#11 error: %s (0x%08lX). AWS error: %s.",
        (void *)pkcs11_lib,
        session,
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
    if (options->filename.ptr != NULL) {
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

    /* Check function list's API version */
    CK_VERSION version = pkcs11_lib->function_list->version;
    if ((version.major != AWS_SUPPORTED_CRYPTOKI_VERSION_MAJOR) ||
        (version.minor < AWS_MIN_SUPPORTED_CRYPTOKI_VERSION_MINOR)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKCS11,
            "id=%p: Library implements PKCS#11 version %" PRIu8 ".%" PRIu8 " but %d.%d compatibility is required",
            (void *)pkcs11_lib,
            version.major,
            version.minor,
            AWS_SUPPORTED_CRYPTOKI_VERSION_MAJOR,
            AWS_MIN_SUPPORTED_CRYPTOKI_VERSION_MINOR);

        aws_raise_error(AWS_IO_PKCS11_ERROR);
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

        rv = pkcs11_lib->function_list->C_Initialize(&init_args);
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

/**
 * Find the slot that meets all criteria:
 * - has a token
 * - if match_slot_id is non-null, then slot IDs must match
 * - if match_token_label is non-null, then labels must match
 * The function fails unless it finds exactly one slot meeting all criteria.
 */
int aws_pkcs11_lib_find_slot_with_token(
    struct aws_pkcs11_lib *pkcs11_lib,
    const aws_pkcs11_t *match_slot_id,
    const struct aws_string *match_token_label,
    aws_pkcs11_t *out_slot_id) {

    CK_SLOT_ID *slot_id_array = NULL;
    CK_SLOT_ID *candidate = NULL;
    CK_TOKEN_INFO info;
    bool success = false;

    /* query number of slots with tokens */
    CK_ULONG num_slots = 0;
    CK_RV rv = pkcs11_lib->function_list->C_GetSlotList(CK_TRUE /*tokenPresent*/, NULL /*pSlotList*/, &num_slots);
    if (rv != CKR_OK) {
        s_raise_ck_error(pkcs11_lib, "C_GetSlotList", rv);
        goto except;
    }

    if (num_slots == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKCS11, "id=%p: No PKCS#11 tokens present in any slot.", (void *)pkcs11_lib);
        aws_raise_error(AWS_IO_PKCS11_ERROR);
        goto except;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_PKCS11, "id=%p: Found %lu slots with tokens. Picking one...", (void *)pkcs11_lib, num_slots);

    /* allocate space for slot IDs */
    slot_id_array = aws_mem_calloc(pkcs11_lib->allocator, num_slots, sizeof(CK_SLOT_ID));

    /* query all slot IDs */
    rv = pkcs11_lib->function_list->C_GetSlotList(CK_TRUE /*tokenPresent*/, slot_id_array, &num_slots);
    if (rv != CKR_OK) {
        s_raise_ck_error(pkcs11_lib, "C_GetSlotList", rv);
        goto except;
    }

    for (size_t i = 0; i < num_slots; ++i) {
        CK_SLOT_ID slot_id_i = slot_id_array[i];

        /* if specific slot_id requested, and this isn't it, then skip */
        if ((match_slot_id != NULL) && (*match_slot_id != slot_id_i)) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_PKCS11,
                "id=%p: Ignoring PKCS#11 token because slot %lu doesn't match %lu",
                (void *)pkcs11_lib,
                slot_id_i,
                *match_slot_id);
            continue;
        }

        /* query token info */
        CK_TOKEN_INFO token_info_i;
        rv = pkcs11_lib->function_list->C_GetTokenInfo(slot_id_i, &token_info_i);
        if (rv != CKR_OK) {
            s_raise_ck_error(pkcs11_lib, "C_GetTokenInfo", rv);
            goto except;
        }

        /* if specific token label requested, and this isn't it, then skip */
        if (match_token_label != NULL) {
            struct aws_byte_cursor label_i = s_trim_padding(token_info_i.label, sizeof(token_info_i.label));
            if (aws_string_eq_byte_cursor(match_token_label, &label_i) == false) {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_PKCS11,
                    "id=%p: Ignoring PKCS#11 token in slot %lu because label '" PRInSTR "' doesn't match '%s'",
                    (void *)pkcs11_lib,
                    slot_id_i,
                    AWS_BYTE_CURSOR_PRI(label_i),
                    aws_string_c_str(match_token_label));
                continue;
            }
        }

        /* this slot is a candidate! */

        /* be sure there's only one candidate */
        if (candidate != NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKCS11,
                "id=%p: Failed to choose PKCS#11 token, multiple tokens match search criteria",
                (void *)pkcs11_lib);
            aws_raise_error(AWS_IO_PKCS11_ERROR);
            goto except;
        }

        /* the new candidate! */
        candidate = &slot_id_array[i];
        memcpy(&info, &token_info_i, sizeof(CK_TOKEN_INFO));
    }

    if (candidate == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKCS11, "id=%p: Failed to find PKCS#11 token which matches search criteria", (void *)pkcs11_lib);
        aws_raise_error(AWS_IO_PKCS11_ERROR);
        goto except;
    }

    /* success! */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_PKCS11,
        "id=%p: Selected PKCS#11 token. slot:%lu label:'" PRInSTR "' manufacturerID:'" PRInSTR "' model:'" PRInSTR
        "' serialNumber:'" PRInSTR "' flags:0x%08lX sessionCount:%lu/%lu rwSessionCount:%lu/%lu"
        " freePublicMemory:%lu/%lu freePrivateMemory:%lu/%lu"
        " hardwareVersion:%" PRIu8 ".%" PRIu8 " firmwareVersion:%" PRIu8 ".%" PRIu8,
        (void *)pkcs11_lib,
        *candidate,
        AWS_BYTE_CURSOR_PRI(s_trim_padding(info.label, sizeof(info.label))),
        AWS_BYTE_CURSOR_PRI(s_trim_padding(info.manufacturerID, sizeof(info.manufacturerID))),
        AWS_BYTE_CURSOR_PRI(s_trim_padding(info.model, sizeof(info.model))),
        AWS_BYTE_CURSOR_PRI(s_trim_padding(info.serialNumber, sizeof(info.serialNumber))),
        info.flags,
        info.ulSessionCount,
        info.ulMaxSessionCount,
        info.ulRwSessionCount,
        info.ulMaxRwSessionCount,
        info.ulFreePublicMemory,
        info.ulTotalPublicMemory,
        info.ulFreePrivateMemory,
        info.ulTotalPrivateMemory,
        info.hardwareVersion.major,
        info.hardwareVersion.minor,
        info.firmwareVersion.major,
        info.firmwareVersion.minor);

    *out_slot_id = *candidate;
    success = true;
    goto finally;

except:
finally:
    aws_mem_release(pkcs11_lib->allocator, slot_id_array);
    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

int aws_pkcs11_lib_open_session(
    struct aws_pkcs11_lib *pkcs11_lib,
    aws_pkcs11_t slot_id,
    aws_pkcs11_t *out_session_handle) {

    CK_SESSION_HANDLE session_handle;
    CK_RV rv = pkcs11_lib->function_list->C_OpenSession(
        slot_id, CKF_SERIAL_SESSION /*flags*/, NULL /*pApplication*/, NULL /*notify*/, &session_handle);
    if (rv != CKR_OK) {
        return s_raise_ck_error(pkcs11_lib, "C_OpenSession", rv);
    }

    /* success! */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_PKCS11, "id=%p session=%lu: Session opened on slot %lu", (void *)pkcs11_lib, session_handle, slot_id);

    *out_session_handle = session_handle;
    return AWS_OP_SUCCESS;
}

void aws_pkcs11_lib_close_session(struct aws_pkcs11_lib *pkcs11_lib, aws_pkcs11_t session_handle) {
    CK_RV rv = pkcs11_lib->function_list->C_CloseSession(session_handle);
    if (rv == CKR_OK) {
        AWS_LOGF_DEBUG(AWS_LS_IO_PKCS11, "id=%p session=%lu: Session closed", (void *)pkcs11_lib, session_handle);
    } else {
        /* Log the error, but we can't really do anything about it */
        AWS_LOGF_WARN(
            AWS_LS_IO_PKCS11,
            "id=%p session=%lu: Ignoring C_CloseSession() failure. PKCS#11 error: %s (0x%08lX).",
            (void *)pkcs11_lib,
            session_handle,
            s_ckr_str(rv),
            rv);
    }
}

int aws_pkcs11_lib_login_user(
    struct aws_pkcs11_lib *pkcs11_lib,
    aws_pkcs11_t session_handle,
    const struct aws_string *optional_user_pin) {

    CK_UTF8CHAR_PTR pin = NULL;
    CK_ULONG pin_len = 0;
    if (optional_user_pin) {
        if (optional_user_pin->len > ULONG_MAX) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKCS11, "id=%p session=%lu: PIN is too long.", (void *)pkcs11_lib, session_handle);
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
        pin_len = (CK_ULONG)optional_user_pin->len;
        pin = (CK_UTF8CHAR_PTR)optional_user_pin->bytes;
    }

    CK_RV rv = pkcs11_lib->function_list->C_Login(session_handle, CKU_USER, pin, pin_len);
    if (rv != CKR_OK) {
        return s_raise_ck_session_error(pkcs11_lib, "C_Login", session_handle, rv);
    }

    /* Success! */
    AWS_LOGF_DEBUG(AWS_LS_IO_PKCS11, "id=%p session=%lu: User logged in", (void *)pkcs11_lib, session_handle);
    return AWS_OP_SUCCESS;
}

/**
 * Find the object that meets all criteria:
 * - is private key
 * - if match_label is non-null, then labels must match
 * The function fails unless it finds exactly one object meeting all criteria.
 */
int aws_pkcs11_lib_find_private_key(
    struct aws_pkcs11_lib *pkcs11_lib,
    aws_pkcs11_t session_handle,
    const struct aws_string *match_label,
    aws_pkcs11_t *out_key_object_handle) {

    bool success = false;

    /* whether C_FindObjectsFinal() must be run */
    bool must_finalize_search = false;

    /* set up search attributes */
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ULONG num_attributes = 1;
    CK_ATTRIBUTE attributes[2] = {
        {
            .type = CKA_CLASS,
            .pValue = &key_class,
            .ulValueLen = sizeof(key_class),
        },
    };

    if (match_label != NULL) {
        if (match_label->len > ULONG_MAX) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKCS11,
                "id=%p session=%lu: private key label is too long.",
                (void *)pkcs11_lib,
                session_handle);
            aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            goto except;
        }

        CK_ATTRIBUTE *attr = &attributes[num_attributes++];
        attr->type = CKA_LABEL;
        attr->pValue = (void *)match_label->bytes;
        attr->ulValueLen = (CK_ULONG)match_label->len;
    }

    /* initialize search */
    CK_RV rv = pkcs11_lib->function_list->C_FindObjectsInit(session_handle, attributes, num_attributes);
    if (rv != CKR_OK) {
        s_raise_ck_session_error(pkcs11_lib, "C_FindObjectsInit", session_handle, rv);
        goto except;
    }

    must_finalize_search = true;

    /* get search results.
     * note that we're asking for 2 objects max, so we can fail if we find more than one */
    CK_OBJECT_HANDLE found_objects[2];
    CK_ULONG num_found = 0;
    rv = pkcs11_lib->function_list->C_FindObjects(session_handle, found_objects, 2 /*max*/, &num_found);
    if (rv != CKR_OK) {
        s_raise_ck_session_error(pkcs11_lib, "C_FindObjects", session_handle, rv);
        goto except;
    }

    if ((num_found == 0) || (found_objects[0] == CK_INVALID_HANDLE)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKCS11,
            "id=%p session=%lu: Failed to find private key on PKCS#11 token which matches search criteria.",
            (void *)pkcs11_lib,
            session_handle);
        aws_raise_error(AWS_IO_PKCS11_ERROR);
        goto except;
    }
    if (num_found > 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKCS11,
            "id=%p session=%lu: Failed to choose private key, multiple objects on PKCS#11 token match search criteria.",
            (void *)pkcs11_lib,
            session_handle);
        aws_raise_error(AWS_IO_PKCS11_ERROR);
        goto except;
    }

    /* Success! */
    AWS_LOGF_TRACE(AWS_LS_IO_PKCS11, "id=%p session=%lu: Found private key.", (void *)pkcs11_lib, session_handle);
    *out_key_object_handle = found_objects[0];
    success = true;
    goto finally;

except:
finally:

    if (must_finalize_search) {
        rv = pkcs11_lib->function_list->C_FindObjectsFinal(session_handle);
        /* don't bother reporting error if we were already failing */
        if ((rv != CKR_OK) && (success == true)) {
            s_raise_ck_session_error(pkcs11_lib, "C_FindObjectsFinal", session_handle, rv);
            success = false;
        }
    }

    return success ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

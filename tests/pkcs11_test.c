/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * See PKCS11.md for instructions on running these tests
 */

#include <aws/io/pkcs11.h>

#include "../source/pkcs11_private.h"

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/environment.h>
#include <aws/common/file.h>
#include <aws/common/mutex.h>
#include <aws/common/process.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* allow strncpy() */
#endif

AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_LIB, "TEST_PKCS11_LIB");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_TOKEN_DIR, "TEST_PKCS11_TOKEN_DIR");

/* Singleton that stores env-var values */
struct pkcs11_tester {
    struct aws_allocator *allocator;
    struct aws_string *shared_lib_path;
    struct aws_string *token_dir;
    struct aws_pkcs11_lib *lib;
};

static struct pkcs11_tester s_pkcs11_tester;
const char *TOKEN_LABEL = "my-token";
const char *TOKEN_LABEL_RSA = "my-rsa-token";
const char *TOKEN_LABEL_EC = "my-ec-token";
const char *SO_PIN = "1111";
const char *USER_PIN = "0000";
const char *DEFAULT_KEY_LABEL = "my-key";
const char *DEFAULT_KEY_ID = "AABBCCDD";

#define TIMEOUT_SEC 10
#define TIMEOUT_MILLIS (AWS_TIMESTAMP_MILLIS * TIMEOUT_SEC)
#define TIMEOUT_NANOS ((uint64_t)AWS_TIMESTAMP_NANOS * TIMEOUT_SEC)

struct pkcs11_key_creation_params {
    const char *key_label;
    const char *key_id;
    const CK_ULONG key_length;
};

/* Wipe out all existing tokens by deleting and recreating the SoftHSM token dir */
static int s_pkcs11_clear_softhsm(void) {
    ASSERT_SUCCESS(aws_directory_delete(s_pkcs11_tester.token_dir, true /*recursive*/));
    ASSERT_SUCCESS(aws_directory_create(s_pkcs11_tester.token_dir));
    return AWS_OP_SUCCESS;
}

static int s_reload_hsm(void) {

    /* Finalize to make sure that softhsm reads new tokens afresh */
    aws_pkcs11_lib_release(s_pkcs11_tester.lib);
    s_pkcs11_tester.lib = NULL;

    /* Load library again */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .initialize_finalize_behavior = AWS_PKCS11_LIB_STRICT_INITIALIZE_FINALIZE,
    };
    s_pkcs11_tester.lib = aws_pkcs11_lib_new(s_pkcs11_tester.allocator, &options);
    ASSERT_NOT_NULL(s_pkcs11_tester.lib, "Failed to load PKCS#11 lib");

    return AWS_OP_SUCCESS;
}

static int s_pkcs11_clear_softhsm_and_reload(void) {

    /* Finalize to make sure that softhsm reads new tokens afresh */
    aws_pkcs11_lib_release(s_pkcs11_tester.lib);
    s_pkcs11_tester.lib = NULL;

    /* Clear token dir */
    ASSERT_SUCCESS(s_pkcs11_clear_softhsm());

    /* Load library again */
    ASSERT_SUCCESS(s_reload_hsm());

    return AWS_OP_SUCCESS;
}

/* Encryption/Decryption only applies to RSA, not ECC */
static int s_pkcs11_rsa_encrypt(
    struct aws_byte_cursor *message,
    struct aws_byte_buf *cipher_text,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE public_key) {

    CK_FUNCTION_LIST *pkcs11_function_list = aws_pkcs11_lib_get_function_list(s_pkcs11_tester.lib);
    struct aws_allocator *allocator = s_pkcs11_tester.allocator;

    CK_MECHANISM mechanism = {.mechanism = CKM_RSA_PKCS};
    CK_RV rv = pkcs11_function_list->C_EncryptInit(session, &mechanism, public_key);
    if (rv != CKR_OK) {
        FAIL("C_EncryptInit fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    CK_ULONG cipher_len = 0;
    rv = pkcs11_function_list->C_Encrypt(session, message->ptr, (CK_ULONG)message->len, NULL, &cipher_len);
    if (rv != CKR_OK) {
        FAIL("C_Encrypt fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    aws_byte_buf_init(cipher_text, allocator, cipher_len);
    rv = pkcs11_function_list->C_Encrypt(
        session, message->ptr, (CK_ULONG)message->len, cipher_text->buffer, &cipher_len);
    if (rv != CKR_OK) {
        FAIL("C_Encrypt fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    cipher_text->len = cipher_len;
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_verify_signature(
    struct aws_byte_cursor *message,
    struct aws_byte_buf *signature,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE public_key,
    CK_MECHANISM_TYPE mechanism_type) {

    CK_FUNCTION_LIST *pkcs11_function_list = aws_pkcs11_lib_get_function_list(s_pkcs11_tester.lib);

    CK_MECHANISM mechanism = {.mechanism = mechanism_type};
    CK_RV rv = pkcs11_function_list->C_VerifyInit(session, &mechanism, public_key);
    if (rv != CKR_OK) {
        FAIL("C_VerifyInit fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    rv = pkcs11_function_list->C_Verify(
        session, message->ptr, (CK_ULONG)message->len, signature->buffer, (CK_ULONG)signature->len);
    if (rv != CKR_OK) {
        FAIL("C_Verify fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_create_rsa_key(
    struct pkcs11_key_creation_params *params,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE *created_private_key,
    CK_OBJECT_HANDLE *created_public_key) {

    CK_FUNCTION_LIST *pkcs11_function_list = aws_pkcs11_lib_get_function_list(s_pkcs11_tester.lib);

    /* We only support RSA keys today. */
    CK_MECHANISM smech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    /* Define key template */
    static CK_BBOOL truevalue = CK_TRUE;
    static CK_BBOOL falsevalue = CK_FALSE;

    /* Set public key. Not sure if setting modulus_bits actually generates key as per that. */
    CK_ATTRIBUTE publickey_template[] = {
        {CKA_VERIFY, &truevalue, sizeof(truevalue)},
        {CKA_MODULUS_BITS, (CK_VOID_PTR)&params->key_length, sizeof(params->key_length)},
    };

    /* Set private key. The parameters here are kind of random, does not affect the test, but trying
     * to mimic what a real key would look like in terms of attributes */
    CK_ATTRIBUTE privatekey_template[] = {
        {CKA_LABEL, (void *)params->key_label, (CK_ULONG)strlen(params->key_label)},
        {CKA_ID, (void *)params->key_id, (CK_ULONG)strlen(params->key_id)},
        {CKA_SIGN, &truevalue, sizeof(truevalue)},
        {CKA_EXTRACTABLE, &falsevalue, sizeof(falsevalue)},
    };
    CK_OBJECT_HANDLE privatekey, publickey = CK_INVALID_HANDLE;
    /* Generate Key pair for signing/verifying */
    CK_RV rv = pkcs11_function_list->C_GenerateKeyPair(
        session,
        &smech,
        publickey_template,
        AWS_ARRAY_SIZE(publickey_template),
        privatekey_template,
        AWS_ARRAY_SIZE(privatekey_template),
        &publickey,
        &privatekey);
    if (rv != CKR_OK) {
        FAIL("C_GenerateKeyPair fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    *created_private_key = privatekey;
    *created_public_key = publickey;
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_create_ec_key(
    struct pkcs11_key_creation_params *params,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE *created_private_key,
    CK_OBJECT_HANDLE *created_public_key) {

    CK_FUNCTION_LIST *pkcs11_function_list = aws_pkcs11_lib_get_function_list(s_pkcs11_tester.lib);

    CK_MECHANISM smech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
    /* Define key template */
    static CK_BBOOL truevalue = CK_TRUE;
    static CK_BBOOL falsevalue = CK_FALSE;
    /* DER encoded params for curve P-256 */
    static CK_BYTE ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_ATTRIBUTE publickey_template[] = {
        {CKA_EC_PARAMS, ec_params, sizeof(ec_params)},
        {CKA_VERIFY, &truevalue, sizeof(truevalue)},
    };

    /* Set private key. The parameters here are kind of random, does not affect the test, but trying
     * to mimic what a real key would look like in terms of attributes */
    CK_ATTRIBUTE privatekey_template[] = {
        {CKA_LABEL, (void *)params->key_label, (CK_ULONG)strlen(params->key_label)},
        {CKA_ID, (void *)params->key_id, (CK_ULONG)strlen(params->key_id)},
        {CKA_SIGN, &truevalue, sizeof(truevalue)},
        {CKA_EXTRACTABLE, &falsevalue, sizeof(falsevalue)},
    };
    CK_OBJECT_HANDLE privatekey, publickey = CK_INVALID_HANDLE;
    /* Generate Key pair for signing/verifying */
    CK_RV rv = pkcs11_function_list->C_GenerateKeyPair(
        session,
        &smech,
        publickey_template,
        AWS_ARRAY_SIZE(publickey_template),
        privatekey_template,
        AWS_ARRAY_SIZE(privatekey_template),
        &publickey,
        &privatekey);
    if (rv != CKR_OK) {
        FAIL("C_GenerateKeyPair fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    *created_private_key = privatekey;
    *created_public_key = publickey;
    return AWS_OP_SUCCESS;
}

/* if tokenInfo is set, finds slot with matching token
 * if tokenInfo is NULL, finds slot with uninitialized token */
static int s_pkcs11_find_slot(const CK_TOKEN_INFO *tokenInfo, CK_SLOT_ID *out_slot) {

    CK_FUNCTION_LIST *pkcs11_function_list = aws_pkcs11_lib_get_function_list(s_pkcs11_tester.lib);
    CK_ULONG ul_slot_count = 0;
    CK_SLOT_ID slot_id = 0;
    CK_RV rv = pkcs11_function_list->C_GetSlotList(CK_TRUE, NULL, &ul_slot_count);
    if (rv != CKR_OK) {
        FAIL("ERROR: Could not get the number of slots.");
    }

    CK_SLOT_ID_PTR p_slot_list = aws_mem_acquire(s_pkcs11_tester.allocator, ul_slot_count * sizeof(CK_SLOT_ID));
    if (p_slot_list == NULL) {
        FAIL("ERROR: Could not allocate memory.");
    }

    rv = pkcs11_function_list->C_GetSlotList(CK_FALSE, p_slot_list, &ul_slot_count);
    if (rv != CKR_OK) {
        FAIL("ERROR: Could not get the slot list.");
    }

    size_t counter = 0;
    for (CK_ULONG i = 0; i < ul_slot_count; i++) {
        CK_TOKEN_INFO curr_token_info;

        rv = pkcs11_function_list->C_GetTokenInfo(p_slot_list[i], &curr_token_info);
        if (rv != CKR_OK) {
            FAIL("ERROR: Could not get info about the token in slot %lu.", p_slot_list[i]);
        }

        if (tokenInfo) {
            if (memcmp(curr_token_info.serialNumber, tokenInfo->serialNumber, sizeof(tokenInfo->serialNumber)) == 0 &&
                memcmp(curr_token_info.label, tokenInfo->label, sizeof(tokenInfo->label)) == 0) {

                slot_id = p_slot_list[i];
                counter++;
            }
        } else {
            /* find slots with uninitialized token */
            if ((curr_token_info.flags & CKF_TOKEN_INITIALIZED) == 0) {
                slot_id = p_slot_list[i];
                counter++;
            }
        }
    }

    aws_mem_release(s_pkcs11_tester.allocator, p_slot_list);

    if (counter == 0) {
        FAIL("ERROR: Could not find a slot/token using --serial, or --token");
    } else if (counter > 1) {
        FAIL("ERROR: Found multiple matching slots/tokens.");
    }
    /* We found just one matching slot */
    *out_slot = slot_id;
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_find_free_slot(CK_SLOT_ID *out_slot) {

    return s_pkcs11_find_slot(NULL, out_slot);
}

/* Creation of slot requires a reload of softhsm, and hence need to re initialize the pkcs11_lib */
static int s_pkcs11_softhsm_create_slot(
    const char *token_name,
    const char *so_pin,
    const char *user_pin,
    CK_SLOT_ID *created_slot) {

    CK_FUNCTION_LIST *pkcs11_function_list = aws_pkcs11_lib_get_function_list(s_pkcs11_tester.lib);
    CK_RV rv;

    /* API expects ' ' padded string */
    CK_UTF8CHAR paddedLabel[32];
    memset(paddedLabel, ' ', sizeof(paddedLabel));
    memcpy(paddedLabel, token_name, strlen(token_name));

    CK_SLOT_ID slot_id = 0;
    ASSERT_SUCCESS(s_pkcs11_find_free_slot(&slot_id));

    rv = pkcs11_function_list->C_InitToken(slot_id, (CK_UTF8CHAR_PTR)so_pin, (CK_ULONG)strlen(so_pin), paddedLabel);
    if (rv != CKR_OK) {
        FAIL("C_InitToken fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    CK_SESSION_HANDLE session;
    rv = pkcs11_function_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        FAIL("C_OpenSession fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    rv = pkcs11_function_list->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)so_pin, (CK_ULONG)strlen(so_pin));
    if (rv != CKR_OK) {
        FAIL("C_Login fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    rv = pkcs11_function_list->C_InitPIN(session, (CK_UTF8CHAR_PTR)user_pin, (CK_ULONG)strlen(user_pin));
    if (rv != CKR_OK) {
        FAIL("C_InitPIN fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    CK_TOKEN_INFO tokenInfo;
    rv = pkcs11_function_list->C_GetTokenInfo(slot_id, &tokenInfo);
    if (rv != CKR_OK) {
        FAIL("C_GetTokenInfo fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    /* Reload the library */
    ASSERT_SUCCESS(s_reload_hsm());

    CK_SLOT_ID new_slot_id = 0;
    ASSERT_SUCCESS(s_pkcs11_find_slot(&tokenInfo, &new_slot_id));
    if (slot_id == new_slot_id) {
        printf("The token has been initialized on slot %lu\n", new_slot_id);
    } else {
        printf("The token has been initialized and is reassigned to slot %lu\n", new_slot_id);
    }

    *created_slot = new_slot_id;
    return AWS_OP_SUCCESS;
}

/*
 * Helper functions to interact with softhsm end
 * */

/* Unload PKCS#11 lib
 * Clear SoftHSM's token dir so that each test ends fresh */
static void s_pkcs11_tester_clean_up(void) {
    aws_pkcs11_lib_release(s_pkcs11_tester.lib);
    s_pkcs11_tester.lib = NULL;
    s_pkcs11_clear_softhsm();
    aws_string_destroy(s_pkcs11_tester.shared_lib_path);
    aws_string_destroy(s_pkcs11_tester.token_dir);
    AWS_ZERO_STRUCT(s_pkcs11_tester);
    aws_io_library_clean_up();
}

/* Read env-vars, raise an error if any necessary ones are missing.
 * Clear SoftHSM's token dir so that each test starts fresh.
 * DO NOT load PKCS#11 lib. */
static int s_pkcs11_tester_init_without_load(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    const struct aws_string *env_var = TEST_PKCS11_LIB;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.shared_lib_path);
    if (s_pkcs11_tester.shared_lib_path == NULL) {
        FAIL("Missing required env-var '%s'\n", aws_string_c_str(env_var));
    }

    env_var = TEST_PKCS11_TOKEN_DIR;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.token_dir);
    if (s_pkcs11_tester.token_dir == NULL) {
        FAIL("Missing required env-var '%s'\n", aws_string_c_str(env_var));
    }

    s_pkcs11_tester.allocator = allocator;

    ASSERT_SUCCESS(s_pkcs11_clear_softhsm());

    return AWS_OP_SUCCESS;
}

/* Read env-vars, raise an error if any necessary ones are missing.
 * Clear SoftHSM's token dir so that each test starts fresh.
 * Load PKCS#11 lib. */
static int s_pkcs11_tester_init(struct aws_allocator *allocator) {
    ASSERT_SUCCESS(s_pkcs11_tester_init_without_load(allocator));

    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .initialize_finalize_behavior = AWS_PKCS11_LIB_STRICT_INITIALIZE_FINALIZE,
    };
    s_pkcs11_tester.lib = aws_pkcs11_lib_new(s_pkcs11_tester.allocator, &options);
    ASSERT_NOT_NULL(s_pkcs11_tester.lib, "Failed to load PKCS#11 lib");

    return AWS_OP_SUCCESS;
}

static int s_pkcs11_tester_init_with_session_login(
    struct aws_allocator *allocator,
    const char *token_label,
    CK_SLOT_ID *created_slot,
    CK_SESSION_HANDLE *session) {

    /* Reset tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(token_label, SO_PIN, USER_PIN, created_slot));

    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, *created_slot, session /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, *session, user_pin));
    aws_string_destroy(user_pin);

    return AWS_OP_SUCCESS;
}

/* Simplest test: Loads and unloads library, calling C_Initialize() and C_Finalize() */
static int s_test_pkcs11_lib_sanity_check(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_sanity_check, s_test_pkcs11_lib_sanity_check)

/* Stress test the DEFAULT_BEHAVIOR for C_Initialize() / C_Finalize() calls */
static int s_test_pkcs11_lib_behavior_default(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init_without_load(allocator));

    struct aws_pkcs11_lib_options options_default_behavior = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .initialize_finalize_behavior = AWS_PKCS11_LIB_DEFAULT_BEHAVIOR,
    };
    struct aws_pkcs11_lib *lib_1 = aws_pkcs11_lib_new(allocator, &options_default_behavior);
    ASSERT_NOT_NULL(lib_1, "Failed to load PKCS#11 lib");

    /* Loading the lib a 2nd time with DEFAULT_BEHAVIOR should be fine,
     * since CKR_CRYPTOKI_ALREADY_INITIALIZED should be ignored. */
    struct aws_pkcs11_lib *lib_2 = aws_pkcs11_lib_new(allocator, &options_default_behavior);
    ASSERT_NOT_NULL(lib_2, "Failed to load a 2nd PKCS#11 lib");

    /* lib_2 should keep working if lib_1 is freed, since C_Finalize() is not called with DEFAULT_BEHAVIOR.
     * (call C_GetInfo() to confirm the lib_2 still works) */
    aws_pkcs11_lib_release(lib_1);
    lib_1 = NULL;

    CK_INFO info;
    ASSERT_INT_EQUALS(CKR_OK, aws_pkcs11_lib_get_function_list(lib_2)->C_GetInfo(&info));

    /* If all libs are unloaded, and another comes online. That should be fine */
    aws_pkcs11_lib_release(lib_2);
    lib_2 = NULL;

    struct aws_pkcs11_lib *lib_3 = aws_pkcs11_lib_new(allocator, &options_default_behavior);
    ASSERT_NOT_NULL(lib_3, "Failed to load a 3rd PKCS#11 lib");

    /* Clean up */
    aws_pkcs11_lib_release(lib_3);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_behavior_default, s_test_pkcs11_lib_behavior_default)

/* Stress test the OMIT_INITIALIZE behavior, where neither C_Initialize() or C_Finalize() is called */
static int s_test_pkcs11_lib_behavior_omit_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init_without_load(allocator));

    struct aws_pkcs11_lib_options options_omit_initialize = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .initialize_finalize_behavior = AWS_PKCS11_LIB_OMIT_INITIALIZE,
    };

    /* Test that we fail gracefully if OMIT_INITIALIZE behavior is used,
     * but no one else has initialized the underlying PKCS#11 library */
    struct aws_pkcs11_lib *pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_ERROR_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED, aws_last_error());

    /* Test that it's fine to use OMIT_INITIALIZE behavior to have the library loaded multiple times. */

    /* First create a lib that DOES call C_Initialize() */
    struct aws_pkcs11_lib_options options_initialize_finalize = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .initialize_finalize_behavior = AWS_PKCS11_LIB_STRICT_INITIALIZE_FINALIZE,
    };
    struct aws_pkcs11_lib *lib_initialize_finalize = aws_pkcs11_lib_new(allocator, &options_initialize_finalize);
    ASSERT_NOT_NULL(lib_initialize_finalize);

    /* Now test that it's fine to create a 2nd lib using OMIT_INITIALIZE */
    struct aws_pkcs11_lib *lib_2 = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NOT_NULL(lib_2);

    /* Clean up */
    aws_pkcs11_lib_release(lib_2);
    aws_pkcs11_lib_release(lib_initialize_finalize);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_behavior_omit_initialize, s_test_pkcs11_lib_behavior_omit_initialize)

/* Stress test the STRICT_INITIALIZE_FINALIZE behavior */
static int s_test_pkcs11_lib_behavior_strict_initialize_finalize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init_without_load(allocator));

    /* Creating the 1st lib should succeed */
    struct aws_pkcs11_lib_options options_initialize_finalize = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .initialize_finalize_behavior = AWS_PKCS11_LIB_STRICT_INITIALIZE_FINALIZE,
    };
    struct aws_pkcs11_lib *lib_1 = aws_pkcs11_lib_new(allocator, &options_initialize_finalize);
    ASSERT_NOT_NULL(lib_1);

    /* Creating the 2nd lib should fail due to already-initialized errors */
    struct aws_pkcs11_lib *lib_2_should_fail = aws_pkcs11_lib_new(allocator, &options_initialize_finalize);
    ASSERT_NULL(lib_2_should_fail);
    ASSERT_INT_EQUALS(AWS_ERROR_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED, aws_last_error());

    /* It should be safe to release a STRICT lib, then create another */
    aws_pkcs11_lib_release(lib_1);
    lib_1 = NULL;

    struct aws_pkcs11_lib *lib_2_should_succeed = aws_pkcs11_lib_new(allocator, &options_initialize_finalize);
    ASSERT_NOT_NULL(lib_2_should_succeed);

    /* Clean up */
    aws_pkcs11_lib_release(lib_2_should_succeed);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_behavior_strict_initialize_finalize, s_test_pkcs11_lib_behavior_strict_initialize_finalize)

static int s_test_pkcs11_session_tests(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Assert that creating a session for an invalid slot fails.
     *
     * NOTE: We omit this part of the test when AddressSanitizer is being used,
     * because SoftHSM v2.2 triggers it in this scenario. I've tried using a
     * suppression file to ignore the issue, but the suppression isn't
     * working and I still don't understand why after 1+ hours of effort.
     * But this ifdef does the trick so that's what I'm doing. */
#if defined(__has_feature)
#    if __has_feature(address_sanitizer)
#        define ADDRESS_SANITIZER_ENABLED 1
#    endif
#endif
#if !ADDRESS_SANITIZER_ENABLED
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    /* we haven't created any slots and we are starting from a clean softhsm, so any slot value is invalid. */
    CK_SLOT_ID slot = 1;
    ASSERT_FAILS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, slot, &session /*out*/));
#endif

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    CK_SESSION_HANDLE first_session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE second_session = CK_INVALID_HANDLE;
    /* Now, creation of a session on a valid slot will be a success */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &first_session /*out*/));
    ASSERT_TRUE(first_session != CK_INVALID_HANDLE);

    /* create one more session */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &second_session /*out*/));
    ASSERT_TRUE(second_session != CK_INVALID_HANDLE);
    ASSERT_TRUE(first_session != second_session);

    /* Close both sessions */
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, first_session);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, second_session);

    /* Clean up */
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_session_tests, s_test_pkcs11_session_tests)

static int s_test_pkcs11_login_tests(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    /* Try to login with in invalid session, we have not created any session on this token
     * So, any session value is invalid */
    struct aws_string *pin = aws_string_new_from_c_str(allocator, USER_PIN);
    CK_SESSION_HANDLE invalid_session = 1UL;
    ASSERT_FAILS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, invalid_session, pin));

    /* Now create a valid session */
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session /*out*/));

    /* Try an invalid pin on a valid slot */
    struct aws_string *invalid_pin = aws_string_new_from_c_str(allocator, "INVALID_PIN");
    ASSERT_FAILS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session, invalid_pin));

    /* Try a valid pin on a valid slot */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session, pin));

    /* A re login should succeed, as we are already logged in now */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session, pin));

    /* Now create one more session */
    CK_SESSION_HANDLE session_2 = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_2 /*out*/));

    /* A re login should succeed, as we are already logged in another session and
     * the spec only requires login once on any of the session in an application
     * */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session_2, pin));

    /* Close the first session */
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session);

    /* A re login should succeed again on the second session, as login is only required once */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session_2, pin));

    /* Close the second session */
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session_2);

    /* Clean up */
    aws_string_destroy(pin);
    aws_string_destroy(invalid_pin);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_login_tests, s_test_pkcs11_login_tests)

static int s_test_pkcs11_find_private_key_for_different_rsa_types(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(TOKEN_LABEL_RSA, SO_PIN, USER_PIN, &created_slot));

    /* Do not close the session while running a test, objects created by a session are cleaned up
     * when the session is closed.
     * http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc386027485
     * */
    /* Open a different session to access the created key, and a different one to create */
    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_access_key /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_create_key /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session_to_access_key, user_pin));

    CK_OBJECT_HANDLE created_priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    char *key_label_1024 = "1024_Key";
    char *key_id_1024 = "1024_id";
    struct pkcs11_key_creation_params params_1024 = {
        .key_label = key_label_1024, .key_id = key_id_1024, .key_length = 1024};
    ASSERT_SUCCESS(s_pkcs11_create_rsa_key(&params_1024, session_to_create_key, &created_priv_key, &created_pub_key));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    struct aws_string *key_label_str = aws_string_new_from_c_str(allocator, key_label_1024);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_str, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_priv_key, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Create another RSA key */
    CK_OBJECT_HANDLE created_key_2048 = CK_INVALID_HANDLE;
    char *key_label_2048 = "2048_Key";
    char *key_id_2048 = "2048_id";
    struct pkcs11_key_creation_params params_2048 = {
        .key_label = key_label_2048, .key_id = key_id_2048, .key_length = 2048};
    ASSERT_SUCCESS(s_pkcs11_create_rsa_key(&params_2048, session_to_create_key, &created_key_2048, &created_pub_key));

    /* Find key */
    struct aws_string *key_label_str_2048 = aws_string_new_from_c_str(allocator, key_label_2048);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_str_2048, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_2048, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Create another RSA key */
    CK_OBJECT_HANDLE created_key_4096 = CK_INVALID_HANDLE;
    char *key_label_4096 = "4096_Key";
    char *key_id_4096 = "4096_id";
    struct pkcs11_key_creation_params params_4096 = {
        .key_label = key_label_4096, .key_id = key_id_4096, .key_length = 4096};
    ASSERT_SUCCESS(s_pkcs11_create_rsa_key(&params_4096, session_to_create_key, &created_key_4096, &created_pub_key));

    /* Find key */
    struct aws_string *key_label_str_4096 = aws_string_new_from_c_str(allocator, key_label_4096);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_str_4096, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_4096, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_string_destroy(user_pin);
    aws_string_destroy(key_label_str);
    aws_string_destroy(key_label_str_2048);
    aws_string_destroy(key_label_str_4096);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key_for_different_rsa_types, s_test_pkcs11_find_private_key_for_different_rsa_types)

static int s_test_pkcs11_find_private_key_for_ec(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    /* Do not close the session while running a test, objects created by a session are cleaned up
     * when the session is closed.
     * http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc386027485
     * */
    /* Open a different session to access the created key, and a different one to create */
    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_access_key /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_create_key /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session_to_access_key, user_pin));

    /* Create an EC key */
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_key_ec_256 = CK_INVALID_HANDLE;
    char *key_label_ec_256 = "EC_256_Key";
    char *key_id_ec_256 = "EC_256_id";
    struct pkcs11_key_creation_params params_ec_256 = {.key_label = key_label_ec_256, .key_id = key_id_ec_256};
    ASSERT_SUCCESS(
        s_pkcs11_create_ec_key(&params_ec_256, session_to_create_key, &created_key_ec_256, &created_pub_key));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    struct aws_string *key_label_str_ec_256 = aws_string_new_from_c_str(allocator, key_label_ec_256);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_str_ec_256, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_ec_256, pkey_handle);
    ASSERT_INT_EQUALS(CKK_EC, pkey_type);

    /* Clean up */
    aws_string_destroy(user_pin);
    aws_string_destroy(key_label_str_ec_256);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key_for_ec, s_test_pkcs11_find_private_key_for_ec)

static int s_test_pkcs11_find_multiple_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    const char *key_label_1 = "RSA_KEY";
    const char *key_id_1 = "BEEFCAFE";
    const char *key_label_2 = "DES_KEY_2";
    const char *key_id_2 = "BEEFCAFEDEAD";

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key_1;
    CK_SESSION_HANDLE session_to_create_key_2;

    /* Open a session to access the created key */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_access_key /*out*/));
    /* Open sessions to create keys, 1 session is probably enough, but test creation with multiple sessions */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_create_key_1 /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_create_key_2 /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session_to_access_key, user_pin));

    CK_OBJECT_HANDLE created_key_1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_key_2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    struct pkcs11_key_creation_params params_1 = {.key_label = key_label_1, .key_id = key_id_1, .key_length = 1024};
    struct pkcs11_key_creation_params params_2 = {.key_label = key_label_2, .key_id = key_id_2, .key_length = 1024};
    ASSERT_SUCCESS(s_pkcs11_create_rsa_key(&params_1, session_to_create_key_1, &created_key_1, &created_pub_key));
    ASSERT_SUCCESS(s_pkcs11_create_rsa_key(&params_2, session_to_create_key_2, &created_key_2, &created_pub_key));

    /* Since there are 2 keys, a lookup without label should fail */
    struct aws_string *key_label_str = aws_string_new_from_c_str(allocator, key_label_1);
    struct aws_string *key_label_2_str = aws_string_new_from_c_str(allocator, key_label_2);
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    ASSERT_FAILS(
        aws_pkcs11_lib_find_private_key(s_pkcs11_tester.lib, session_to_access_key, NULL, &pkey_handle, &pkey_type));

    /* a lookup with label for the first key should find the first key */
    pkey_handle = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_str, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_1, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* a lookup with label for the second key should find the second key */
    pkey_handle = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_2_str, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_2, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_string_destroy(key_label_str);
    aws_string_destroy(key_label_2_str);
    aws_string_destroy(user_pin);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session_to_access_key);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session_to_create_key_1);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session_to_create_key_2);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_multiple_private_key, s_test_pkcs11_find_multiple_private_key)

static int s_test_pkcs11_find_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    const char *key_label_1 = "RSA_KEY";
    const char *key_id_1 = "BEEFCAFE";
    const char *label_1 = "label!@#$%^&*-_=+{}[]<>?,./():_1";
    const char *so_pin_1 = "qwertyuioplaksjdhfgbn341269504732";
    const char *user_pin_1 = "341269504732";

    /* Create a new slot, Use values other than defaults for label/pins */
    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(label_1, so_pin_1, user_pin_1, &created_slot));

    /* Do not close the session while running a test, objects created by a session are cleaned up
     * when the session is closed.
     * http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc386027485
     * */
    /* Open a different session to access the created key, and a different one to create */
    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_access_key /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(s_pkcs11_tester.lib, created_slot, &session_to_create_key /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, user_pin_1);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(s_pkcs11_tester.lib, session_to_access_key, user_pin));

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    struct pkcs11_key_creation_params params = {.key_label = key_label_1, .key_id = key_id_1, .key_length = 1024};
    ASSERT_SUCCESS(s_pkcs11_create_rsa_key(&params, session_to_create_key, &created_key, &created_pub_key));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    struct aws_string *key_label_str = aws_string_new_from_c_str(allocator, key_label_1);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        s_pkcs11_tester.lib, session_to_access_key, key_label_str, &pkey_handle, &pkey_type));
    ASSERT_TRUE(CK_INVALID_HANDLE != pkey_handle);
    ASSERT_INT_EQUALS(created_key, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Since there is only one key, a lookup without label should also return the key */
    pkey_handle = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(s_pkcs11_tester.lib, session_to_access_key, NULL, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_string_destroy(key_label_str);
    aws_string_destroy(user_pin);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session_to_access_key);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session_to_create_key);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key, s_test_pkcs11_find_private_key)

static int s_test_pkcs11_find_slot(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* softhsm does not like ;| as part of label */
    const char *const label = "label!@#$%^&*-_=+{}[]<>?,./():_1";

    const char *const so_pin = "qwertyuioplaksjdhfgbn341269504732";
    const char *const user_pin = "341269504732";

    CK_SLOT_ID slot_id = 0;
    /*
     * Softhsm always has one uninitialized token which is returned by the GetSlotList() API,
     * so there is no way to start without any slot at all
     * */

    /* Call aws_pkcs11_lib_find_slot_with_token with 1 token, but no matching criteria */
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_slot_with_token(s_pkcs11_tester.lib, NULL /*match_slot_id*/, NULL, &slot_id /*out*/));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(label, so_pin, user_pin, &created_slot));

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but no matching criteria */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(
        aws_pkcs11_lib_find_slot_with_token(s_pkcs11_tester.lib, NULL /*match_slot_id*/, NULL, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but match the slot this time */
    uint64_t match_slot_id = created_slot;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(s_pkcs11_tester.lib, &match_slot_id, NULL, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but match the label this time */
    slot_id = 0;
    struct aws_string *match_label = aws_string_new_from_c_str(allocator, label);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, NULL /*match_slot_id*/, match_label, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot, slot_id);

    /* clear softhsm and make sure that no tokens match with previous slot/label */
    ASSERT_SUCCESS(s_pkcs11_clear_softhsm_and_reload());

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the uninitialized token,
     * and assert that previous label does not match anymore
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, NULL /*match_slot_id*/, match_label /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Clean up */
    aws_string_destroy(match_label);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_slot, s_test_pkcs11_find_slot)

static int s_test_pkcs11_find_slot_many_tokens(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens and load library */
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    const char *const label_1 = "label_1";
    const char *const label_2 = "label_2";

    const char *const so_pin_1 = "ABCD";
    const char *const so_pin_2 = "0111";

    const char *const user_pin_1 = "ABCD";
    const char *const user_pin_2 = "0111";

    /* Create 2 new slots.
     * WARNING: SoftHSM may change ALL the slot_ids whenever a new token is added, and the library is reloaded */
    CK_SLOT_ID slot_id = (CK_SLOT_ID)-1;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(label_1, so_pin_1, user_pin_1, &slot_id));
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(label_2, so_pin_2, user_pin_2, &slot_id));

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, match the label 1 this time */
    struct aws_string *match_label_1 = aws_string_new_from_c_str(allocator, label_1);
    CK_SLOT_ID created_slot_1 = (CK_SLOT_ID)-1;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, NULL /*match_slot_id*/, match_label_1 /*match_token_label*/, &created_slot_1 /*out*/));

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, match the label 2 this time */
    struct aws_string *match_label_2 = aws_string_new_from_c_str(allocator, label_2);
    CK_SLOT_ID created_slot_2 = (CK_SLOT_ID)-1;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, NULL /*match_slot_id*/, match_label_2 /*match_token_label*/, &created_slot_2 /*out*/));
    ASSERT_TRUE(created_slot_2 != created_slot_1);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens on softhsm, but no matching criteria */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, NULL /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the slot 1 this time */
    const uint64_t match_slot_id_1 = created_slot_1;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, &match_slot_id_1 /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the slot 2 this time */
    const uint64_t match_slot_id_2 = created_slot_2;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, &match_slot_id_2 /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_2, slot_id);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with 3 tokens,
     * but a mismatch for a slot and label should return error
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib,
        &match_slot_id_1 /*match_slot_id*/,
        match_label_2 /*match_token_label*/,
        &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib,
        &match_slot_id_2 /*match_slot_id*/,
        match_label_1 /*match_token_label*/,
        &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);
    /*
     * Call aws_pkcs11_lib_find_slot_with_token with 3 tokens,
     * but match for both, slot and label should return success
     * */
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib,
        &match_slot_id_1 /*match_slot_id*/,
        match_label_1 /*match_token_label*/,
        &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_1, slot_id);

    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib,
        &match_slot_id_2 /*match_slot_id*/,
        match_label_2 /*match_token_label*/,
        &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_2, slot_id);

    /* clear softhsm and make sure that no tokens match with previous slot/label */
    ASSERT_SUCCESS(s_pkcs11_clear_softhsm_and_reload());

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the uninitialized token,
     * and assert that previous label does not match anymore
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        s_pkcs11_tester.lib, NULL /*match_slot_id*/, match_label_2 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Clean up */
    aws_string_destroy(match_label_1);
    aws_string_destroy(match_label_2);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_slot_many_tokens, s_test_pkcs11_find_slot_many_tokens)

static int s_test_pkcs11_prepare_rsa_2048_sign(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE *pri_key,
    CK_OBJECT_HANDLE *pub_key) {
    struct pkcs11_key_creation_params params = {
        .key_label = DEFAULT_KEY_LABEL, .key_id = DEFAULT_KEY_ID, .key_length = 2048};
    return s_pkcs11_create_rsa_key(&params, session, pri_key, pub_key);
}

static int s_test_pkcs11_prepare_ec_256_sign(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE *pri_key,
    CK_OBJECT_HANDLE *pub_key) {
    struct pkcs11_key_creation_params params = {
        .key_label = DEFAULT_KEY_LABEL, .key_id = DEFAULT_KEY_ID, .key_length = 256};
    return s_pkcs11_create_ec_key(&params, session, pri_key, pub_key);
}

/* Encryption/Decryption only applies to RSA, not ECC */
static int s_test_pkcs11_rsa_decrypt(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* Reset PKCS#11 tokens, load library */
    CK_SLOT_ID created_slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    s_pkcs11_tester_init_with_session_login(allocator, TOKEN_LABEL_RSA, &created_slot, &session);

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(s_test_pkcs11_prepare_rsa_2048_sign(session, &created_key, &created_pub_key));

    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_c_str("ABCDEFGHIJKL");
    struct aws_byte_buf output_buf; /* initialized later */
    AWS_ZERO_STRUCT(output_buf);

    /* Encrypt our text */
    ASSERT_SUCCESS(s_pkcs11_rsa_encrypt(&input_cursor, &output_buf, session, created_pub_key));

    struct aws_byte_cursor cipher_text = aws_byte_cursor_from_buf(&output_buf);
    struct aws_byte_buf output_decrypted; /* initialized later */
    AWS_ZERO_STRUCT(output_decrypted);
    ASSERT_SUCCESS(aws_pkcs11_lib_decrypt(
        s_pkcs11_tester.lib, session, created_key, CKK_RSA, cipher_text, allocator, &output_decrypted));

    ASSERT_BIN_ARRAYS_EQUALS(output_decrypted.buffer, output_decrypted.len, input_cursor.ptr, input_cursor.len);

    /* Assert that sign fails for invalid / mismatch key type */
    /* TODO: Move ASSERT_FAILS to ASSERT_ERROR */
    CK_KEY_TYPE unsupported_key_type = CKK_GENERIC_SECRET;
    aws_byte_buf_clean_up(&output_decrypted);
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        s_pkcs11_tester.lib, session, created_key, unsupported_key_type, cipher_text, allocator, &output_decrypted));

    /* Invalid session handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        s_pkcs11_tester.lib, CK_INVALID_HANDLE, created_key, CKK_RSA, cipher_text, allocator, &output_decrypted));

    /* Invalid key handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        s_pkcs11_tester.lib, session, CK_INVALID_HANDLE, CKK_RSA, cipher_text, allocator, &output_decrypted));

    struct aws_byte_cursor empty_message_to_decrypt = aws_byte_cursor_from_c_str("");
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        s_pkcs11_tester.lib, session, created_key, CKK_RSA, empty_message_to_decrypt, allocator, &output_decrypted));
    /* Clean up */
    aws_byte_buf_clean_up(&output_buf);
    aws_byte_buf_clean_up(&output_decrypted);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pkcs11_rsa_decrypt, s_test_pkcs11_rsa_decrypt)

static int s_test_pkcs11_sign_rsa(struct aws_allocator *allocator, void *ctx, enum aws_tls_hash_algorithm digest_alg) {
    (void)ctx;
    /* Reset PKCS#11 tokens, load library */
    CK_SLOT_ID created_slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    s_pkcs11_tester_init_with_session_login(allocator, TOKEN_LABEL_RSA, &created_slot, &session);

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(s_test_pkcs11_prepare_rsa_2048_sign(session, &created_key, &created_pub_key));

    struct aws_byte_cursor message_to_sign = aws_byte_cursor_from_c_str("ABCDEFGHIJKL");
    struct aws_byte_buf signature; /* initialized later */
    AWS_ZERO_STRUCT(signature);

    /* Sign a message */
    ASSERT_SUCCESS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        session,
        created_key,
        CKK_RSA,
        message_to_sign,
        allocator,
        digest_alg,
        AWS_TLS_SIGNATURE_RSA,
        &signature));

    struct aws_byte_buf prefixed_input;
    /* There is no good way to validate without this, as we append this prefix internally before signing. */
    struct aws_byte_cursor prefix;
    ASSERT_SUCCESS(aws_get_prefix_to_rsa_sig(digest_alg, &prefix));

    aws_byte_buf_init(&prefixed_input, allocator, message_to_sign.len + prefix.len); /* cannot fail */
    aws_byte_buf_write(&prefixed_input, prefix.ptr, prefix.len);
    aws_byte_buf_write_from_whole_cursor(&prefixed_input, message_to_sign);
    struct aws_byte_cursor input_message_to_verify = aws_byte_cursor_from_buf(&prefixed_input);

    /* Verify the signature */
    ASSERT_SUCCESS(
        s_pkcs11_verify_signature(&input_message_to_verify, &signature, session, created_pub_key, CKM_RSA_PKCS));

    /* Assert that sign fails for invalid key type */
    CK_KEY_TYPE unsupported_key_type = CKK_GENERIC_SECRET;
    aws_byte_buf_clean_up(&signature);
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        session,
        created_key,
        unsupported_key_type,
        message_to_sign,
        allocator,
        digest_alg,
        AWS_TLS_SIGNATURE_RSA,
        &signature));

    /* Invalid session handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        CK_INVALID_HANDLE,
        created_key,
        CKK_RSA,
        message_to_sign,
        allocator,
        digest_alg,
        AWS_TLS_SIGNATURE_RSA,
        &signature));

    /* Invalid key handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        session,
        CK_INVALID_HANDLE,
        CKK_RSA,
        message_to_sign,
        allocator,
        digest_alg,
        AWS_TLS_SIGNATURE_RSA,
        &signature));

    /* Clean up */
    aws_byte_buf_clean_up(&prefixed_input);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}

static int s_test_pkcs11_sign_rsa_sha1(struct aws_allocator *allocator, void *ctx) {
    return s_test_pkcs11_sign_rsa(allocator, ctx, AWS_TLS_HASH_SHA1);
}
AWS_TEST_CASE(pkcs11_sign_rsa_sha1, s_test_pkcs11_sign_rsa_sha1)

static int s_test_pkcs11_sign_rsa_sha512(struct aws_allocator *allocator, void *ctx) {
    return s_test_pkcs11_sign_rsa(allocator, ctx, AWS_TLS_HASH_SHA512);
}
AWS_TEST_CASE(pkcs11_sign_rsa_sha512, s_test_pkcs11_sign_rsa_sha512)

static int s_test_pkcs11_sign_rsa_sha384(struct aws_allocator *allocator, void *ctx) {
    return s_test_pkcs11_sign_rsa(allocator, ctx, AWS_TLS_HASH_SHA384);
}
AWS_TEST_CASE(pkcs11_sign_rsa_sha384, s_test_pkcs11_sign_rsa_sha384)

static int s_test_pkcs11_sign_rsa_sha256(struct aws_allocator *allocator, void *ctx) {
    return s_test_pkcs11_sign_rsa(allocator, ctx, AWS_TLS_HASH_SHA256);
}
AWS_TEST_CASE(pkcs11_sign_rsa_sha256, s_test_pkcs11_sign_rsa_sha256)

static int s_test_pkcs11_sign_rsa_sha224(struct aws_allocator *allocator, void *ctx) {
    return s_test_pkcs11_sign_rsa(allocator, ctx, AWS_TLS_HASH_SHA224);
}
AWS_TEST_CASE(pkcs11_sign_rsa_sha224, s_test_pkcs11_sign_rsa_sha224)

static int s_verify_bigint(
    struct aws_allocator *allocator,
    uint8_t *ptr,
    size_t len_in,
    uint8_t *ptr_out,
    size_t len_out) {
    struct aws_byte_buf buffer;
    struct aws_byte_cursor src_array = aws_byte_cursor_from_array(ptr, len_in);
    aws_byte_buf_init(&buffer, allocator, len_in + 4);
    ASSERT_SUCCESS(aws_pkcs11_asn1_enc_ubigint(&buffer, src_array));
    ASSERT_INT_EQUALS(len_out, buffer.len);
    for (size_t i = 0; i < len_out; i++) {
        ASSERT_HEX_EQUALS(ptr_out[i], buffer.buffer[i], "Mismatch at position %zu", i);
    }
    aws_byte_buf_clean_up(&buffer);
    return AWS_OP_SUCCESS;
}

static int s_test_pkcs11_asn1_bigint(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /*
     * ECDSA relies on this working correct, so test this first to avoid intermittent failures
     */
    uint8_t pos_int_1_in[4] = {0x12, 0x34, 0x56, 0x78};
    uint8_t pos_int_1_out[6] = {0x02, 0x04, 0x12, 0x34, 0x56, 0x78};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_1_in, sizeof(pos_int_1_in), pos_int_1_out, sizeof(pos_int_1_out)));
    uint8_t pos_int_2_in[4] = {0x00, 0x34, 0x56, 0x78};
    uint8_t pos_int_2_out[5] = {0x02, 0x03, 0x34, 0x56, 0x78};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_2_in, sizeof(pos_int_2_in), pos_int_2_out, sizeof(pos_int_2_out)));
    uint8_t pos_int_3_in[4] = {0x00, 0x00, 0x56, 0x78};
    uint8_t pos_int_3_out[4] = {0x02, 0x02, 0x56, 0x78};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_3_in, sizeof(pos_int_3_in), pos_int_3_out, sizeof(pos_int_3_out)));
    uint8_t pos_int_4_in[4] = {0x00, 0x00, 0x00, 0x78};
    uint8_t pos_int_4_out[3] = {0x02, 0x01, 0x78};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_4_in, sizeof(pos_int_4_in), pos_int_4_out, sizeof(pos_int_4_out)));
    uint8_t pos_int_5_in[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t pos_int_5_out[3] = {0x02, 0x01, 0x00};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_5_in, sizeof(pos_int_5_in), pos_int_5_out, sizeof(pos_int_5_out)));
    uint8_t pos_int_6_in[1] = {0}; // actually we specify 0-length, but not all compilers support empty array
    uint8_t pos_int_6_out[3] = {0x02, 0x01, 0x00};
    ASSERT_SUCCESS(s_verify_bigint(allocator, pos_int_6_in, 0, pos_int_6_out, sizeof(pos_int_6_out)));
    uint8_t pos_int_7_in[4] = {0x00, 0x84, 0x56, 0x78};
    uint8_t pos_int_7_out[6] = {0x02, 0x04, 0x00, 0x84, 0x56, 0x78};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_7_in, sizeof(pos_int_7_in), pos_int_7_out, sizeof(pos_int_7_out)));
    uint8_t pos_int_8_in[4] = {0x82, 0x34, 0x56, 0x78};
    uint8_t pos_int_8_out[7] = {0x02, 0x05, 0x00, 0x82, 0x34, 0x56, 0x78};
    ASSERT_SUCCESS(
        s_verify_bigint(allocator, pos_int_8_in, sizeof(pos_int_8_in), pos_int_8_out, sizeof(pos_int_8_out)));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_asn1_bigint, s_test_pkcs11_asn1_bigint)

static int s_decode_asn1(struct aws_byte_cursor *src, uint8_t *identifier, struct aws_byte_cursor *split) {
    ASSERT_TRUE(src->len >= 2, "ASN1 structure too small for header, length=%u", src->len);
    *identifier = src->ptr[0];
    uint8_t small_len = src->ptr[1];
    src->ptr += 2;
    src->len -= 2;
    ASSERT_TRUE(small_len < 0x80, "ASN1 multi-byte length specified: %u", small_len);
    ASSERT_TRUE(small_len <= src->len, "ASN1 length too big: %u > %u", small_len, src->len);
    *split = aws_byte_cursor_from_array(src->ptr, small_len);
    src->ptr += small_len;
    src->len -= small_len;
    return AWS_OP_SUCCESS;
}

static int s_write_bigint(struct aws_byte_buf *buf, struct aws_byte_cursor *num, size_t len) {
    if (num->len > len && num->len > 1 && num->ptr[0] == 0x00 && (num->ptr[1] & 0x80) != 0) {
        // only scenario we allow length to be bigger
        num->ptr++;
        num->len--;
    }
    ASSERT_TRUE(num->len <= len, "ASN1 number is too big: %u > %u", num->len, len);
    if (num->len < len) {
        uint8_t fill = num->ptr[0] & 0x80 ? 0xff : 0x00;
        while (len > num->len) {
            aws_byte_buf_write(buf, &fill, 1);
            len--;
        }
    }
    aws_byte_buf_write_from_whole_cursor(buf, *num);
    return AWS_OP_SUCCESS;
}

static int s_test_pkcs11_sign_ec(
    struct aws_allocator *allocator,
    void *ctx,
    int sig_len,
    int (*prepare)(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *pri_key, CK_OBJECT_HANDLE *pub_key)) {
    (void)ctx;
    /* Reset PKCS#11 tokens, load library */
    CK_SLOT_ID created_slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    s_pkcs11_tester_init_with_session_login(allocator, TOKEN_LABEL_EC, &created_slot, &session);

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(prepare(session, &created_key, &created_pub_key));

    struct aws_byte_cursor message_to_sign = aws_byte_cursor_from_c_str("ABCDEFGHIJKL");
    struct aws_byte_buf signature;  /* initialized later */
    struct aws_byte_buf sig_verify; /* initialized later */
    AWS_ZERO_STRUCT(signature);
    AWS_ZERO_STRUCT(sig_verify);

    /* Sign a message */
    ASSERT_SUCCESS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        session,
        created_key,
        CKK_EC,
        message_to_sign,
        allocator,
        AWS_TLS_HASH_UNKNOWN, // digest handled entirely by S2N
        AWS_TLS_SIGNATURE_ECDSA,
        &signature));

    /*
     * Verify we have a structure of 2 ASN1 encoded integers
     */
    uint8_t identifier;
    struct aws_byte_cursor sig_curs = aws_byte_cursor_from_buf(&signature);
    struct aws_byte_cursor struct_body;
    ASSERT_SUCCESS(s_decode_asn1(&sig_curs, &identifier, &struct_body));
    ASSERT_HEX_EQUALS(0x30, identifier); // compound structure
    ASSERT_INT_EQUALS(sig_curs.len, 0);
    struct aws_byte_cursor r;
    struct aws_byte_cursor s;
    ASSERT_SUCCESS(s_decode_asn1(&struct_body, &identifier, &r));
    ASSERT_HEX_EQUALS(0x02, identifier); // integer
    ASSERT_SUCCESS(s_decode_asn1(&struct_body, &identifier, &s));
    ASSERT_HEX_EQUALS(0x02, identifier); // integer
    ASSERT_INT_EQUALS(struct_body.len, 0);
    // rewrite signature in format PKCS11 expects
    aws_byte_buf_init(&sig_verify, allocator, sig_len * 2);
    s_write_bigint(&sig_verify, &r, sig_len);
    s_write_bigint(&sig_verify, &s, sig_len);
    struct aws_byte_cursor message_to_verify = aws_byte_cursor_from_c_str("ABCDEFGHIJKL");

    /* Verify the signature */
    ASSERT_SUCCESS(s_pkcs11_verify_signature(&message_to_verify, &sig_verify, session, created_pub_key, CKM_ECDSA));

    aws_byte_buf_clean_up(&signature);
    aws_byte_buf_clean_up(&sig_verify);

    /* Assert that sign fails for invalid key type */
    CK_KEY_TYPE unsupported_key_type = CKK_GENERIC_SECRET;
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        session,
        created_key,
        unsupported_key_type,
        message_to_sign,
        allocator,
        AWS_TLS_HASH_UNKNOWN,
        AWS_TLS_SIGNATURE_ECDSA,
        &signature));

    /* Invalid session handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        CK_INVALID_HANDLE,
        created_key,
        CKK_EC,
        message_to_sign,
        allocator,
        AWS_TLS_HASH_UNKNOWN,
        AWS_TLS_SIGNATURE_ECDSA,
        &signature));

    /* Invalid key handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        s_pkcs11_tester.lib,
        session,
        CK_INVALID_HANDLE,
        CKK_EC,
        message_to_sign,
        allocator,
        AWS_TLS_HASH_UNKNOWN,
        AWS_TLS_SIGNATURE_ECDSA,
        &signature));

    /* Clean up */
    aws_byte_buf_clean_up(&signature);
    aws_pkcs11_lib_close_session(s_pkcs11_tester.lib, session);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}

static int s_test_pkcs11_sign_ec_256(struct aws_allocator *allocator, void *ctx) {
    return s_test_pkcs11_sign_ec(allocator, ctx, 32, s_test_pkcs11_prepare_ec_256_sign);
}
AWS_TEST_CASE(pkcs11_sign_ec_256, s_test_pkcs11_sign_ec_256)

#ifndef BYO_CRYPTO

/*
 * Helper function to interact with softhsm begin
 */
static int s_run_cmd(const char *fmt, ...) {
    char cmd[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    printf("Executing command: %s\n", cmd);
    struct aws_run_command_options cmd_opts = {.command = cmd};
    struct aws_run_command_result cmd_result;
    ASSERT_SUCCESS(aws_run_command_result_init(s_pkcs11_tester.allocator, &cmd_result));
    ASSERT_SUCCESS(aws_run_command(s_pkcs11_tester.allocator, &cmd_opts, &cmd_result));
    int ret_code = cmd_result.ret_code;
    aws_run_command_result_cleanup(&cmd_result);
    return ret_code;
}

struct tls_tester {
    struct {
        struct aws_mutex mutex;
        struct aws_condition_variable cvar;

        bool server_results_ready;
        int server_error_code;

        bool client_results_ready;
        int client_error_code;
    } synced;
};
static struct tls_tester s_tls_tester;

static bool s_are_client_results_ready(void *user_data) {
    (void)user_data;
    return s_tls_tester.synced.client_results_ready;
}

static bool s_are_server_results_ready(void *user_data) {
    (void)user_data;
    return s_tls_tester.synced.server_results_ready;
}

/* callback when client TLS connection established (or failed) */
static void s_on_tls_client_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS test client setup. error_code=%s", aws_error_name(error_code));

    /* if negotiation succeeds: shutdown channel nicely
     * if negotiation fails: store error code and notify main thread */
    if (error_code == 0) {
        aws_channel_shutdown(channel, 0);
    } else {
        aws_mutex_lock(&s_tls_tester.synced.mutex);
        s_tls_tester.synced.client_error_code = error_code;
        s_tls_tester.synced.client_results_ready = true;
        aws_mutex_unlock(&s_tls_tester.synced.mutex);
        aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
    }
}

/* callback when client TLS connection finishes shutdown (doesn't fire if setup failed) */
static void s_on_tls_client_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS test client shutdown. error_code=%s", aws_error_name(error_code));

    /* store error code and notify main thread  */
    aws_mutex_lock(&s_tls_tester.synced.mutex);
    s_tls_tester.synced.client_error_code = error_code;
    s_tls_tester.synced.client_results_ready = true;
    aws_mutex_unlock(&s_tls_tester.synced.mutex);
    aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
}

/* callback when server TLS connection established (or failed) */
static void s_on_tls_server_channel_setup(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS test server setup. error_code=%s", aws_error_name(error_code));

    if (error_code == 0) {
        /* do nothing, the client will shut down this channel */
        return;
    } else {
        /* store error code and notify main thread  */
        aws_mutex_lock(&s_tls_tester.synced.mutex);
        s_tls_tester.synced.server_error_code = error_code;
        s_tls_tester.synced.server_results_ready = true;
        aws_mutex_unlock(&s_tls_tester.synced.mutex);
        aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
    }
}

/* callback when server TLS connection established (or failed) */
static void s_on_tls_server_channel_shutdown(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;
    (void)user_data;
    AWS_LOGF_INFO(AWS_LS_IO_PKCS11, "TLS test server shutdown. error_code=%s", aws_error_name(error_code));

    /* store error code and notify main thread  */
    aws_mutex_lock(&s_tls_tester.synced.mutex);
    s_tls_tester.synced.server_error_code = error_code;
    s_tls_tester.synced.server_results_ready = true;
    aws_mutex_unlock(&s_tls_tester.synced.mutex);
    aws_condition_variable_notify_all(&s_tls_tester.synced.cvar);
}

/* Connect a client client and server, where the client is using PKCS#11 for private key operations */
static int s_test_pkcs11_tls_negotiation_succeeds_common(
    struct aws_allocator *allocator,
    const char *token_label,
    const char *p8key_path,
    const char *cert_path,
    const char *pkey_path) {
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Create token for provided key */

    CK_SLOT_ID slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(token_label, SO_PIN, USER_PIN, &slot));

    aws_pkcs11_lib_release(s_pkcs11_tester.lib);
    s_pkcs11_tester.lib = NULL;

    /* use softhsm2-util to import key */
    ASSERT_SUCCESS(s_run_cmd(
        "softhsm2-util --import %s --module \"%s\" --slot %lu --label %s --id %s --pin %s",
        p8key_path,
        aws_string_c_str(s_pkcs11_tester.shared_lib_path),
        slot,
        DEFAULT_KEY_LABEL,
        DEFAULT_KEY_ID,
        USER_PIN));

    ASSERT_SUCCESS(s_reload_hsm());

    /* Set up resources that aren't specific to server or client */
    ASSERT_SUCCESS(aws_mutex_init(&s_tls_tester.synced.mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&s_tls_tester.synced.cvar));

    struct aws_event_loop_group *event_loop_group =
        aws_event_loop_group_new_default(allocator, 1, NULL /*shutdown_opts*/);
    ASSERT_NOT_NULL(event_loop_group);

    struct aws_host_resolver_default_options resolver_opts = {
        .el_group = event_loop_group,
    };
    struct aws_host_resolver *host_resolver = aws_host_resolver_new_default(allocator, &resolver_opts);
    ASSERT_NOT_NULL(host_resolver);

    /* use randomly named local domain socket */
    struct aws_socket_endpoint endpoint = {.address = {0}, .port = 0};
    {
        struct aws_byte_buf addr_buf = aws_byte_buf_from_empty_array(endpoint.address, sizeof(endpoint.address));
        ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&addr_buf, aws_byte_cursor_from_c_str("testsock-")));

        struct aws_uuid addr_uuid;
        ASSERT_SUCCESS(aws_uuid_init(&addr_uuid));
        ASSERT_SUCCESS(aws_uuid_to_str(&addr_uuid, &addr_buf));

        ASSERT_TRUE(aws_byte_buf_write_from_whole_cursor(&addr_buf, aws_byte_cursor_from_c_str(".sock")));
    }

    struct aws_socket_options sock_opts = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_LOCAL,
        .connect_timeout_ms = TIMEOUT_MILLIS,
    };

    /* Set up a server that does mutual TLS. The server will not use PKCS#11 */

    struct aws_tls_ctx_options server_tls_opts;
    ASSERT_SUCCESS(
        aws_tls_ctx_options_init_default_server_from_path(&server_tls_opts, allocator, cert_path, pkey_path));

    /* trust the client's self-signed certificate */
    ASSERT_SUCCESS(
        aws_tls_ctx_options_override_default_trust_store_from_path(&server_tls_opts, NULL /*ca_path*/, cert_path));

    aws_tls_ctx_options_set_verify_peer(&server_tls_opts, true);

    struct aws_tls_ctx *server_tls_ctx = aws_tls_server_ctx_new(allocator, &server_tls_opts);
    ASSERT_NOT_NULL(server_tls_ctx);
    aws_tls_ctx_options_clean_up(&server_tls_opts);

    struct aws_tls_connection_options server_tls_connection_opts;
    aws_tls_connection_options_init_from_ctx(&server_tls_connection_opts, server_tls_ctx);

    struct aws_server_bootstrap *server_bootstrap = aws_server_bootstrap_new(allocator, event_loop_group);
    ASSERT_NOT_NULL(server_bootstrap);

    struct aws_server_socket_channel_bootstrap_options server_listener_sock_opts = {
        .bootstrap = server_bootstrap,
        .host_name = endpoint.address,
        .port = endpoint.port,
        .socket_options = &sock_opts,
        .tls_options = &server_tls_connection_opts,
        .incoming_callback = s_on_tls_server_channel_setup,
        .shutdown_callback = s_on_tls_server_channel_shutdown,
    };

    struct aws_socket *server_listener_sock = aws_server_bootstrap_new_socket_listener(&server_listener_sock_opts);
    ASSERT_NOT_NULL(server_listener_sock);

    /* Set up a client that does mutual TLS, using PKCS#11 for private key operations */

    struct aws_tls_ctx_options client_tls_opts;

#    if 1 /* Toggle this to run without actually using PKCS#11. Useful for debugging this test. */
    struct aws_tls_ctx_pkcs11_options client_pkcs11_tls_opts = {
        .pkcs11_lib = s_pkcs11_tester.lib,
        .token_label = aws_byte_cursor_from_c_str(token_label),
        .user_pin = aws_byte_cursor_from_c_str(USER_PIN),
        .private_key_object_label = aws_byte_cursor_from_c_str(DEFAULT_KEY_LABEL),
        .cert_file_path = aws_byte_cursor_from_c_str(cert_path),
    };
    ASSERT_SUCCESS(
        aws_tls_ctx_options_init_client_mtls_with_pkcs11(&client_tls_opts, allocator, &client_pkcs11_tls_opts));
#    else
    ASSERT_SUCCESS(aws_tls_ctx_options_init_client_mtls_from_path(&client_tls_opts, allocator, cert_path, pkey_path));
#    endif

    /* trust the server's self-signed certificate */
    ASSERT_SUCCESS(
        aws_tls_ctx_options_override_default_trust_store_from_path(&client_tls_opts, NULL /*ca_path*/, cert_path));

    struct aws_tls_ctx *client_tls_ctx = aws_tls_client_ctx_new(allocator, &client_tls_opts);
    ASSERT_NOT_NULL(client_tls_ctx);
    aws_tls_ctx_options_clean_up(&client_tls_opts);

    struct aws_client_bootstrap_options client_bootstrap_opts = {
        .event_loop_group = event_loop_group,
        .host_resolver = host_resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_opts);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("localhost");
    struct aws_tls_connection_options client_tls_connection_opts;
    aws_tls_connection_options_init_from_ctx(&client_tls_connection_opts, client_tls_ctx);
    ASSERT_SUCCESS(aws_tls_connection_options_set_server_name(&client_tls_connection_opts, allocator, &server_name));
    struct aws_socket_channel_bootstrap_options client_channel_opts = {
        .bootstrap = client_bootstrap,
        .host_name = endpoint.address,
        .port = endpoint.port,
        .socket_options = &sock_opts,
        .tls_options = &client_tls_connection_opts,
        .setup_callback = s_on_tls_client_channel_setup,
        .shutdown_callback = s_on_tls_client_channel_shutdown,
    };

    /* finally, tell the client to connect */
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_opts));

    /* Wait for connection to go through */

    /* CRITICAL SECTION */
    {
        ASSERT_SUCCESS(aws_mutex_lock(&s_tls_tester.synced.mutex));

        /* wait for client to successfully create connection and tear it down */
        ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
            &s_tls_tester.synced.cvar,
            &s_tls_tester.synced.mutex,
            (int64_t)TIMEOUT_NANOS,
            s_are_client_results_ready,
            NULL /*user_data*/));
        ASSERT_INT_EQUALS(0, s_tls_tester.synced.client_error_code);

        /* ensure the server also had a good experience */
        ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
            &s_tls_tester.synced.cvar,
            &s_tls_tester.synced.mutex,
            (int64_t)TIMEOUT_NANOS,
            s_are_server_results_ready,
            NULL /*user_data*/));
        ASSERT_INT_EQUALS(0, s_tls_tester.synced.server_error_code);

        ASSERT_SUCCESS(aws_mutex_unlock(&s_tls_tester.synced.mutex));
    }
    /* CRITICAL SECTION */

    /* clean up */
    aws_tls_ctx_release(client_tls_ctx);
    aws_client_bootstrap_release(client_bootstrap);
    aws_tls_connection_options_clean_up(&client_tls_connection_opts);

    aws_server_bootstrap_destroy_socket_listener(server_bootstrap, server_listener_sock);
    aws_tls_connection_options_clean_up(&server_tls_connection_opts);
    aws_server_bootstrap_release(server_bootstrap);
    aws_tls_ctx_release(server_tls_ctx);
    aws_host_resolver_release(host_resolver);
    aws_event_loop_group_release(event_loop_group);

    /* wait for event-loop threads to wrap up */
    aws_thread_set_managed_join_timeout_ns(TIMEOUT_NANOS * 10);
    ASSERT_SUCCESS(aws_thread_join_all_managed());

    aws_condition_variable_clean_up(&s_tls_tester.synced.cvar);
    aws_mutex_clean_up(&s_tls_tester.synced.mutex);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}

/* Connect a client and server, where the client is using PKCS#11 RSA certificate for private key operations */
static int s_test_pkcs11_tls_rsa_negotiation_succeeds(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    return s_test_pkcs11_tls_negotiation_succeeds_common(
        allocator, TOKEN_LABEL_RSA, "unittests.p8", "unittests.crt", "unittests.key");
}
AWS_TEST_CASE(pkcs11_tls_rsa_negotiation_succeeds, s_test_pkcs11_tls_rsa_negotiation_succeeds)

/* Connect a client and server, where the client is using PKCS#11 EC certificate for private key operations */
static int s_test_pkcs11_tls_ec_negotiation_succeeds(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    return s_test_pkcs11_tls_negotiation_succeeds_common(
        allocator, TOKEN_LABEL_EC, "ec_unittests.p8", "ec_unittests.crt", "ec_unittests.key");
}
AWS_TEST_CASE(pkcs11_tls_ec_negotiation_succeeds, s_test_pkcs11_tls_ec_negotiation_succeeds)
#endif /* !BYO_CRYPTO */

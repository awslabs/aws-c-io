/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * See PKCS11.md for instructions on running these tests
 */

#include <aws/io/pkcs11.h>
#include <aws/io/private/pkcs11_private.h>
#include <unistd.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/testing/aws_test_harness.h>

AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_LIB, "TEST_PKCS11_LIB");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_TOKEN_DIR, "TEST_PKCS11_TOKEN_DIR");

/* Singleton that stores env-var values */
struct pkcs11_tester {
    struct aws_allocator *allocator;
    struct aws_string *shared_lib_path;
    struct aws_string *token_dir;
};

static struct pkcs11_tester s_pkcs11_tester;
const char *TOKEN_LABEL = "label";
const char *SO_PIN = "qwerty";
const char *USER_PIN = "341269504732";
const char *DEFAULT_KEY_LABEL = "Key-Label";
const char *DEFAULT_KEY_ID = "ABBCCDDEEFF";
CK_KEY_TYPE SUPPORTED_KEY_TYPE = CKK_RSA;

struct pkcs11_key_creation_params {
    const char *key_label;
    const char *key_id;
    const CK_ULONG key_length;
};

/*
 * Helper functions to interact with softhsm begin
 * */

/* Helper pkcs functions to provision/setup/clear softhsm tokens/keys */
static void s_pkcs11_clear_softhsm(void) {
    /* trim trailing slash from token_dir if necessary */
    char token_dir[512] = {'\0'};
    strncpy(token_dir, aws_string_c_str(s_pkcs11_tester.token_dir), sizeof(token_dir));
    if (token_dir[strlen(token_dir) - 1] == '/') {
        token_dir[strlen(token_dir) - 1] = '\0';
    }

    char cmd[1024] = {'\0'};
    /* TODO: Support this cross platform, leverage dir util methods from aws-c-common */
    snprintf(cmd, sizeof(cmd), "rm -rf %s/*", token_dir);
    printf("Executing command: %s\n", cmd);
    AWS_FATAL_ASSERT(system(cmd) == 0);

    snprintf(cmd, sizeof(cmd), "mkdir -p %s", token_dir);
    printf("Executing command: %s\n", cmd);
    AWS_FATAL_ASSERT(system(cmd) == 0);
}

static struct aws_pkcs11_lib *s_reload_hsm(
    struct aws_allocator *allocator,
    bool is_already_loaded,
    struct aws_pkcs11_lib *current_lib) {

    /* Finalize if needed */
    if (is_already_loaded) {
        /* Finalize to make sure that softhsm reads new tokens afresh */
        aws_pkcs11_lib_release(current_lib);
    }
    /* Load library again */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    return pkcs11_lib;
}

static struct aws_pkcs11_lib *s_pkcs11_clear_softhsm_and_reload(
    struct aws_allocator *allocator,
    bool is_already_loaded,
    struct aws_pkcs11_lib *current_lib) {

    s_pkcs11_clear_softhsm();
    return s_reload_hsm(allocator, is_already_loaded, current_lib);
}

static int s_pkcs11_encrypt(
    CK_FUNCTION_LIST_PTR pkcs11_function_list,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *message,
    struct aws_byte_buf *cipher_text,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE public_key) {

    /* We only support RSA keys today. */
    CK_MECHANISM mechanism = {.mechanism = CKM_RSA_PKCS};
    CK_RV rv = pkcs11_function_list->C_EncryptInit(session, &mechanism, public_key);

    if (rv != CKR_OK) {
        FAIL("C_EncryptInit fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    CK_ULONG cipher_len = 0;
    rv = pkcs11_function_list->C_Encrypt(session, message->ptr, message->len, NULL, &cipher_len);

    if (rv != CKR_OK) {
        FAIL("C_Encrypt fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    aws_byte_buf_init(cipher_text, allocator, cipher_len);
    rv = pkcs11_function_list->C_Encrypt(session, message->ptr, message->len, cipher_text->buffer, &cipher_len);

    if (rv != CKR_OK) {
        FAIL("C_Encrypt fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    cipher_text->len = cipher_len;
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_verify_signature(
    CK_FUNCTION_LIST_PTR pkcs11_function_list,
    struct aws_byte_cursor *message,
    struct aws_byte_buf *signature,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE public_key) {

    /* We only support RSA keys today. */
    CK_MECHANISM mechanism = {.mechanism = CKM_RSA_PKCS};
    CK_RV rv = pkcs11_function_list->C_VerifyInit(session, &mechanism, public_key);

    if (rv != CKR_OK) {
        FAIL("C_VerifyInit fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    rv = pkcs11_function_list->C_Verify(session, message->ptr, message->len, signature->buffer, signature->len);

    if (rv != CKR_OK) {
        FAIL("C_Verify fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_create_key(
    CK_FUNCTION_LIST_PTR pkcs11_function_list,
    struct pkcs11_key_creation_params *params,
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE *created_private_key,
    CK_OBJECT_HANDLE *created_public_key) {

    /* We only support RSA keys today. */
    CK_MECHANISM smech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
    /* Define key template */
    static CK_BBOOL truevalue = TRUE;
    static CK_BBOOL falsevalue = FALSE;

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

/* if tokenInfo is set, finds slot with matching token
 * if tokenInfo is NULL, finds slot with uninitialized token */
static int s_pkcs11_find_slot(
    CK_FUNCTION_LIST_PTR pkcs11_function_list,
    const CK_TOKEN_INFO *tokenInfo,
    CK_SLOT_ID *out_slot) {

    CK_ULONG ul_slot_count;
    CK_SLOT_ID slot_id = 0;
    CK_RV rv = pkcs11_function_list->C_GetSlotList(CK_TRUE, NULL, &ul_slot_count);
    if (rv != CKR_OK) {
        FAIL("ERROR: Could not get the number of slots.\n");
    }

    CK_SLOT_ID_PTR p_slot_list = aws_mem_acquire(s_pkcs11_tester.allocator, ul_slot_count * sizeof(CK_SLOT_ID));
    if (p_slot_list == NULL) {
        FAIL("ERROR: Could not allocate memory.\n");
    }

    rv = pkcs11_function_list->C_GetSlotList(CK_FALSE, p_slot_list, &ul_slot_count);
    if (rv != CKR_OK) {
        FAIL("ERROR: Could not get the slot list.\n");
    }

    size_t counter = 0;
    for (CK_ULONG i = 0; i < ul_slot_count; i++) {
        CK_TOKEN_INFO curr_token_info;

        rv = pkcs11_function_list->C_GetTokenInfo(p_slot_list[i], &curr_token_info);
        if (rv != CKR_OK) {
            FAIL("ERROR: Could not get info about the token in slot %lu.\n", p_slot_list[i]);
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
        FAIL("ERROR: Could not find a slot/token using --serial, or --token\n");
    } else if (counter > 1) {
        FAIL("ERROR: Found multiple matching slots/tokens.\n");
    }
    /* We found just one matching slot */
    *out_slot = slot_id;
    return AWS_OP_SUCCESS;
}

static int s_pkcs11_find_free_slot(CK_FUNCTION_LIST_PTR pkcs11_function_list, CK_SLOT_ID *out_slot) {

    return s_pkcs11_find_slot(pkcs11_function_list, NULL, out_slot);
}

/* Creation of slot requires a reload of softhsm, and hence need to re initialize the pkcs11_lib */
static int s_pkcs11_softhsm_create_slot(
    struct aws_allocator *allocator,
    struct aws_pkcs11_lib **pkcs11_lib, /* Re initialize the library */
    const char *token_name,
    const char *so_pin,
    const char *user_pin,
    CK_SLOT_ID *created_slot) {

    ASSERT_NOT_NULL(*pkcs11_lib);
    CK_RV rv;

    /* API expects ' ' padded string */
    CK_UTF8CHAR paddedLabel[32];
    memset(paddedLabel, ' ', sizeof(paddedLabel));
    memcpy(paddedLabel, token_name, strlen(token_name));

    CK_FUNCTION_LIST_PTR pkcs11_function_list = aws_pkcs11_lib_get_function_list(*pkcs11_lib);

    CK_SLOT_ID slot_id = 0;
    ASSERT_SUCCESS(s_pkcs11_find_free_slot(pkcs11_function_list, &slot_id));

    rv = pkcs11_function_list->C_InitToken(slot_id, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin), paddedLabel);
    if (rv != CKR_OK) {
        FAIL("C_InitToken fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    CK_SESSION_HANDLE session;
    rv = pkcs11_function_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        FAIL("C_OpenSession fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    rv = pkcs11_function_list->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin));
    if (rv != CKR_OK) {
        FAIL("C_Login fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }

    rv = pkcs11_function_list->C_InitPIN(session, (CK_UTF8CHAR_PTR)user_pin, strlen(user_pin));
    if (rv != CKR_OK) {
        FAIL("C_InitPIN fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    CK_TOKEN_INFO tokenInfo;
    rv = pkcs11_function_list->C_GetTokenInfo(slot_id, &tokenInfo);
    if (rv != CKR_OK) {
        FAIL("C_GetTokenInfo fails: PKCS#11 error: %s (0x%08lX)", aws_pkcs11_ckr_str(rv), rv);
    }
    /* Reload the library */
    struct aws_pkcs11_lib *new_pkcs_lib = s_reload_hsm(allocator, TRUE, *pkcs11_lib);
    *pkcs11_lib = new_pkcs_lib;
    if (pkcs11_lib == NULL) {
        FAIL("reload hsm failed");
    }

    CK_SLOT_ID new_slot_id = 0;
    ASSERT_SUCCESS(s_pkcs11_find_slot(pkcs11_function_list, &tokenInfo, &new_slot_id));
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

static void s_pkcs11_tester_clean_up(void) {
    aws_string_destroy(s_pkcs11_tester.shared_lib_path);
    aws_string_destroy(s_pkcs11_tester.token_dir);
    s_pkcs11_tester.allocator = NULL;
    aws_io_library_clean_up();
}

/* Read env-vars.
 * Raise an error if any necessary ones are missing */
static int s_pkcs11_tester_init(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    const struct aws_string *env_var = TEST_PKCS11_LIB;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.shared_lib_path);
    if (s_pkcs11_tester.shared_lib_path == NULL) {
        goto missing;
    }

    env_var = TEST_PKCS11_TOKEN_DIR;
    aws_get_environment_value(allocator, env_var, &s_pkcs11_tester.token_dir);
    if (s_pkcs11_tester.token_dir == NULL) {
        goto missing;
    }

    s_pkcs11_tester.allocator = allocator;
    return AWS_OP_SUCCESS;

missing:
    printf("Missing required env-var '%s'\n", aws_string_c_str(env_var));
    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

static int s_setup_test(
    struct aws_allocator *allocator,
    struct aws_pkcs11_lib **pkcs11_lib,
    CK_SLOT_ID *created_slot,
    CK_SESSION_HANDLE *session) {
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Always start with a clean state, and get a handle to reloaded lib */
    *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN, created_slot));

    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(*pkcs11_lib, *created_slot, session /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(*pkcs11_lib, *session, user_pin));
    aws_string_destroy(user_pin);

    return AWS_OP_SUCCESS;
}

/* Simplest test: Loads and unloads library, calling C_Initialize() and C_Finalize() */
static int s_test_pkcs11_lib_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Clean up */
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_initialize, s_test_pkcs11_lib_initialize)

/* Test that we can use the `omit_initialize` option to have the library loaded multiple times */
static int s_test_pkcs11_lib_omit_initialize(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    struct aws_pkcs11_lib_options options_normal = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };

    struct aws_pkcs11_lib_options options_omit_initialize = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
        .omit_initialize = true,
    };

    /* First test that we fail gracefully if we omit_initialize, but no one else has initialized it yet either */
    struct aws_pkcs11_lib *pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_IO_PKCS11_ERROR, aws_last_error());

    /* Next test that we can load the library twice by using omit_initialize the second time we load it */
    struct aws_pkcs11_lib *pkcs11_lib_1 = aws_pkcs11_lib_new(allocator, &options_normal);
    ASSERT_NOT_NULL(pkcs11_lib_1);

    struct aws_pkcs11_lib *pkcs11_lib_2 = aws_pkcs11_lib_new(allocator, &options_omit_initialize);
    ASSERT_NOT_NULL(pkcs11_lib_2);

    /* Next test that omit_initialize is required if someone else already initialized the library */
    pkcs11_lib_should_fail = aws_pkcs11_lib_new(allocator, &options_normal);
    ASSERT_NULL(pkcs11_lib_should_fail);
    ASSERT_INT_EQUALS(AWS_IO_PKCS11_ERROR, aws_last_error());

    /* Clean up */
    aws_pkcs11_lib_release(pkcs11_lib_2);
    aws_pkcs11_lib_release(pkcs11_lib_1);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_lib_omit_initialize, s_test_pkcs11_lib_omit_initialize)

static int s_test_pkcs11_session_tests(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);

    /* Try creating a session for an invalid slot */
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    /* We havent created any slots and we are starting from a clean softhsm, so any slot value is invalid */
    CK_SLOT_ID slot = 1;
    ASSERT_FAILS(aws_pkcs11_lib_open_session(pkcs11_lib, slot, &session /*out*/));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    CK_SESSION_HANDLE first_session = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE second_session = CK_INVALID_HANDLE;
    /* Now, creation of a session on a valid slot will be a success */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &first_session /*out*/));
    ASSERT_TRUE(first_session != CK_INVALID_HANDLE);

    /* create one more session */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &second_session /*out*/));
    ASSERT_TRUE(second_session != CK_INVALID_HANDLE);
    ASSERT_TRUE(first_session != second_session);

    /* Close both sessions */
    aws_pkcs11_lib_close_session(pkcs11_lib, first_session);
    aws_pkcs11_lib_close_session(pkcs11_lib, second_session);

    /* Clean up */
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_session_tests, s_test_pkcs11_session_tests)

static int s_test_pkcs11_login_tests(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    /* Try to login with in invalid session, we have not created any session on this token
     * So, any session value is invalid */
    struct aws_string *pin = aws_string_new_from_c_str(allocator, USER_PIN);
    CK_SESSION_HANDLE invalid_session = 1UL;
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, invalid_session, pin));

    /* Now create a valid session */
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session /*out*/));

    /* Try an invalid pin on a valid slot */
    struct aws_string *invalid_pin = aws_string_new_from_c_str(allocator, "INVALID_PIN");
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, session, invalid_pin));

    /* Try a valid pin on a valid slot */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session, pin));

    /* A re login should fail, as we are already logged in now */
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, session, pin));

    /* Now create one more session */
    CK_SESSION_HANDLE session_2 = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_2 /*out*/));

    /* A re login should fail, as we are already logged in another session and
     * the spec only allows login once on any of the session in an application
     * */
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, session_2, pin));

    /* Close the first session */
    aws_pkcs11_lib_close_session(pkcs11_lib, session);

    /* A re login should fail again on the second session, as login is only required once */
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, session_2, pin));

    /* Close the second session */
    aws_pkcs11_lib_close_session(pkcs11_lib, session_2);

    /* Clean up */
    aws_string_destroy(pin);
    aws_string_destroy(invalid_pin);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_login_tests, s_test_pkcs11_login_tests)

static int s_test_pkcs11_find_private_key_for_different_types(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);
    CK_FUNCTION_LIST_PTR pkcs11_function_list = aws_pkcs11_lib_get_function_list(pkcs11_lib);

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    /* Do not close the session while running a test, objects created by a session are cleaned up
     * when the session is closed.
     * http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc386027485
     * */
    /* Open a different session to access the created key, and a different one to create */
    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_access_key /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_to_access_key, user_pin));

    CK_OBJECT_HANDLE created_priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    char *key_label_1024 = "1024_Key";
    char *key_id_1024 = "1024_id";
    struct pkcs11_key_creation_params params_1024 = {
        .key_label = key_label_1024, .key_id = key_id_1024, .key_length = 1024};
    ASSERT_SUCCESS(s_pkcs11_create_key(
        pkcs11_function_list, &params_1024, session_to_create_key, &created_priv_key, &created_pub_key));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    struct aws_string *key_label_str = aws_string_new_from_c_str(allocator, key_label_1024);
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib, session_to_access_key, key_label_str, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_priv_key, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Create another RSA key */
    CK_OBJECT_HANDLE created_key_2048 = CK_INVALID_HANDLE;
    char *key_label_2048 = "2048_Key";
    char *key_id_2048 = "2048_id";
    struct pkcs11_key_creation_params params_2048 = {
        .key_label = key_label_2048, .key_id = key_id_2048, .key_length = 2048};
    ASSERT_SUCCESS(s_pkcs11_create_key(
        pkcs11_function_list, &params_2048, session_to_create_key, &created_key_2048, &created_pub_key));

    /* Find key */
    struct aws_string *key_label_str_2048 = aws_string_new_from_c_str(allocator, key_label_2048);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        pkcs11_lib, session_to_access_key, key_label_str_2048, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_2048, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Create another RSA key */
    CK_OBJECT_HANDLE created_key_4096 = CK_INVALID_HANDLE;
    char *key_label_4096 = "4096_Key";
    char *key_id_4096 = "4096_id";
    struct pkcs11_key_creation_params params_4096 = {
        .key_label = key_label_4096, .key_id = key_id_4096, .key_length = 4096};
    ASSERT_SUCCESS(s_pkcs11_create_key(
        pkcs11_function_list, &params_4096, session_to_create_key, &created_key_4096, &created_pub_key));

    /* Find key */
    struct aws_string *key_label_str_4096 = aws_string_new_from_c_str(allocator, key_label_4096);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(
        pkcs11_lib, session_to_access_key, key_label_str_4096, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_4096, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_string_destroy(user_pin);
    aws_string_destroy(key_label_str);
    aws_string_destroy(key_label_str_2048);
    aws_string_destroy(key_label_str_4096);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_access_key);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key_for_different_types, s_test_pkcs11_find_private_key_for_different_types)

static int s_test_pkcs11_find_multiple_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);
    CK_FUNCTION_LIST_PTR pkcs11_function_list = aws_pkcs11_lib_get_function_list(pkcs11_lib);

    const char *key_label_1 = "RSA_KEY";
    const char *key_id_1 = "BEEFCAFE";
    const char *key_label_2 = "DES_KEY_2";
    const char *key_id_2 = "BEEFCAFEDEAD";

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN, &created_slot));

    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key_1;
    CK_SESSION_HANDLE session_to_create_key_2;

    /* Open a session to access the created key */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_access_key /*out*/));
    /* Open sessions to create keys, 1 session is probably enough, but test creation with multiple sessions */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key_1 /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key_2 /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, USER_PIN);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_to_access_key, user_pin));

    CK_OBJECT_HANDLE created_key_1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_key_2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    struct pkcs11_key_creation_params params_1 = {.key_label = key_label_1, .key_id = key_id_1, .key_length = 1024};
    struct pkcs11_key_creation_params params_2 = {.key_label = key_label_2, .key_id = key_id_2, .key_length = 1024};
    ASSERT_SUCCESS(s_pkcs11_create_key(
        pkcs11_function_list, &params_1, session_to_create_key_1, &created_key_1, &created_pub_key));
    ASSERT_SUCCESS(s_pkcs11_create_key(
        pkcs11_function_list, &params_2, session_to_create_key_2, &created_key_2, &created_pub_key));

    /* Since there are 2 keys, a lookup without label should fail */
    struct aws_string *key_label_str = aws_string_new_from_c_str(allocator, key_label_1);
    struct aws_string *key_label_2_str = aws_string_new_from_c_str(allocator, key_label_2);
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    ASSERT_FAILS(aws_pkcs11_lib_find_private_key(pkcs11_lib, session_to_access_key, NULL, &pkey_handle, &pkey_type));

    /* a lookup with label for the first key should find the first key */
    pkey_handle = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib, session_to_access_key, key_label_str, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_1, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* a lookup with label for the second key should find the second key */
    pkey_handle = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib, session_to_access_key, key_label_2_str, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key_2, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_string_destroy(key_label_str);
    aws_string_destroy(key_label_2_str);
    aws_string_destroy(user_pin);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_access_key);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key_1);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key_2);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_multiple_private_key, s_test_pkcs11_find_multiple_private_key)

static int s_test_pkcs11_find_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);
    CK_FUNCTION_LIST_PTR pkcs11_function_list = aws_pkcs11_lib_get_function_list(pkcs11_lib);

    const char *key_label_1 = "RSA_KEY";
    const char *key_id_1 = "BEEFCAFE";
    const char *label_1 = "label!@#$%^&*-_=+{}[]<>?,./():_1";
    const char *so_pin_1 = "qwertyuioplaksjdhfgbn341269504732";
    const char *user_pin_1 = "341269504732";

    /* Create a new slot, Use values other than defaults for label/pins */
    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, label_1, so_pin_1, user_pin_1, &created_slot));

    /* Do not close the session while running a test, objects created by a session are cleaned up
     * when the session is closed.
     * http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc386027485
     * */
    /* Open a different session to access the created key, and a different one to create */
    CK_SESSION_HANDLE session_to_access_key;
    CK_SESSION_HANDLE session_to_create_key;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_access_key /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key /*out*/));

    /* Login user */
    struct aws_string *user_pin = aws_string_new_from_c_str(allocator, user_pin_1);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_to_access_key, user_pin));

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    struct pkcs11_key_creation_params params = {.key_label = key_label_1, .key_id = key_id_1, .key_length = 1024};
    ASSERT_SUCCESS(
        s_pkcs11_create_key(pkcs11_function_list, &params, session_to_create_key, &created_key, &created_pub_key));

    /* Find key */
    CK_OBJECT_HANDLE pkey_handle = CK_INVALID_HANDLE;
    CK_KEY_TYPE pkey_type;
    struct aws_string *key_label_str = aws_string_new_from_c_str(allocator, key_label_1);
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib, session_to_access_key, key_label_str, &pkey_handle, &pkey_type));
    ASSERT_TRUE(CK_INVALID_HANDLE != pkey_handle);
    ASSERT_INT_EQUALS(created_key, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Since there is only one key, a lookup without label should also return the key */
    pkey_handle = CK_INVALID_HANDLE;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_private_key(pkcs11_lib, session_to_access_key, NULL, &pkey_handle, &pkey_type));
    ASSERT_INT_EQUALS(created_key, pkey_handle);
    ASSERT_INT_EQUALS(CKK_RSA, pkey_type);

    /* Clean up */
    aws_string_destroy(key_label_str);
    aws_string_destroy(user_pin);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_access_key);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key, s_test_pkcs11_find_private_key)

static int s_test_pkcs11_find_slot(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);

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
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, NULL /*match_slot_id*/, NULL, &slot_id /*out*/));

    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    CK_SLOT_ID created_slot = 0;
    ASSERT_SUCCESS(s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, label, so_pin, user_pin, &created_slot));

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but no matching criteria */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, NULL /*match_slot_id*/, NULL, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but match the slot this time */
    uint64_t match_slot_id = created_slot;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, &match_slot_id, NULL, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but match the label this time */
    slot_id = 0;
    struct aws_string *match_label = aws_string_new_from_c_str(allocator, label);
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, NULL /*match_slot_id*/, match_label, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot, slot_id);

    /* clear softhsm and make sure that no tokens match with previous slot/label */
    pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, TRUE, pkcs11_lib);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the uninitialized token,
     * and assert that previous label does not match anymore
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, match_label /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Clean up */
    aws_string_destroy(match_label);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_slot, s_test_pkcs11_find_slot)

static int s_test_pkcs11_find_slot_many_tokens(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Always start with a clean state, and get a handle to reloaded lib */
    struct aws_pkcs11_lib *pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, FALSE, NULL);

    const char *const label_1 = "label_1";
    const char *const label_2 = "label_2";

    const char *const so_pin_1 = "ABCD";
    const char *const so_pin_2 = "0111";

    const char *const user_pin_1 = "ABCD";
    const char *const user_pin_2 = "0111";

    /* Create 2 new slots */
    CK_SLOT_ID created_slot_1 = 0;
    CK_SLOT_ID created_slot_2 = 0;
    /* Create a new slot, this reloads the softhsm library but the labels/slots remain intact */
    ASSERT_SUCCESS(
        s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, label_1, so_pin_1, user_pin_1, &created_slot_1));
    ASSERT_SUCCESS(
        s_pkcs11_softhsm_create_slot(allocator, &pkcs11_lib, label_2, so_pin_2, user_pin_2, &created_slot_2));

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens on softhsm, but no matching criteria */
    CK_SLOT_ID slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the slot 1 this time */
    const uint64_t match_slot_id_1 = created_slot_1;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_1 /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the slot 2 this time */
    const uint64_t match_slot_id_2 = created_slot_2;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_2 /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_2, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the label 1 this time */
    struct aws_string *match_label_1 = aws_string_new_from_c_str(allocator, label_1);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, match_label_1 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_1, slot_id);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the label 2 this time */
    struct aws_string *match_label_2 = aws_string_new_from_c_str(allocator, label_2);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, match_label_2 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_2, slot_id);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with 3 tokens,
     * but a mismatch for a slot and label should return error
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_1 /*match_slot_id*/, match_label_2 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_2 /*match_slot_id*/, match_label_1 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);
    /*
     * Call aws_pkcs11_lib_find_slot_with_token with 3 tokens,
     * but match for both, slot and label should return success
     * */
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_1 /*match_slot_id*/, match_label_1 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_1, slot_id);

    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_2 /*match_slot_id*/, match_label_2 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS(created_slot_2, slot_id);

    /* clear softhsm and make sure that no tokens match with previous slot/label */
    pkcs11_lib = s_pkcs11_clear_softhsm_and_reload(allocator, TRUE, pkcs11_lib);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the free token,
     * and assert that previous slot id does not match anymore
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, &match_slot_id_2 /*match_slot_id*/, NULL /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the uninitialized token,
     * and assert that previous label does not match anymore
     * */
    slot_id = (CK_SLOT_ID)-1;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(
        pkcs11_lib, NULL /*match_slot_id*/, match_label_2 /*match_token_label*/, &slot_id /*out*/));
    ASSERT_INT_EQUALS((CK_SLOT_ID)-1, slot_id);

    /* Clean up */
    aws_string_destroy(match_label_1);
    aws_string_destroy(match_label_2);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_slot_many_tokens, s_test_pkcs11_find_slot_many_tokens)

static int s_test_pkcs11_decrypt(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    CK_SLOT_ID created_slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    struct aws_pkcs11_lib *pkcs11_lib = NULL;
    s_setup_test(allocator, &pkcs11_lib, &created_slot, &session);
    CK_FUNCTION_LIST_PTR pkcs11_function_list = aws_pkcs11_lib_get_function_list(pkcs11_lib);

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    struct pkcs11_key_creation_params params = {
        .key_label = DEFAULT_KEY_LABEL, .key_id = DEFAULT_KEY_ID, .key_length = 2048};
    ASSERT_SUCCESS(s_pkcs11_create_key(pkcs11_function_list, &params, session, &created_key, &created_pub_key));

    struct aws_byte_cursor input_cursor = aws_byte_cursor_from_c_str("ABCDEFGHIJKL");
    struct aws_byte_buf output_buf; /* initialized later */
    AWS_ZERO_STRUCT(output_buf);

    /* Encrypt our text */
    ASSERT_SUCCESS(
        s_pkcs11_encrypt(pkcs11_function_list, allocator, &input_cursor, &output_buf, session, created_pub_key));

    struct aws_byte_cursor cipher_text = aws_byte_cursor_from_buf(&output_buf);
    struct aws_byte_buf output_decrypted; /* initialized later */
    AWS_ZERO_STRUCT(output_decrypted);
    ASSERT_SUCCESS(aws_pkcs11_lib_decrypt(
        pkcs11_lib, session, created_key, SUPPORTED_KEY_TYPE, cipher_text, allocator, &output_decrypted));

    ASSERT_BIN_ARRAYS_EQUALS(output_decrypted.buffer, output_decrypted.len, input_cursor.ptr, input_cursor.len);

    /* Assert that sign fails for non RSA key type */
    CK_KEY_TYPE unsupported_key_type = CKK_EC;
    aws_byte_buf_clean_up(&output_decrypted);
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        pkcs11_lib, session, created_key, unsupported_key_type, cipher_text, allocator, &output_decrypted));

    /* Invalid session handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        pkcs11_lib, CK_INVALID_HANDLE, created_key, SUPPORTED_KEY_TYPE, cipher_text, allocator, &output_decrypted));

    /* Invalid key handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        pkcs11_lib, session, CK_INVALID_HANDLE, SUPPORTED_KEY_TYPE, cipher_text, allocator, &output_decrypted));

    struct aws_byte_cursor empty_message_to_decrypt = aws_byte_cursor_from_c_str("");
    ASSERT_FAILS(aws_pkcs11_lib_decrypt(
        pkcs11_lib, session, created_key, SUPPORTED_KEY_TYPE, empty_message_to_decrypt, allocator, &output_decrypted));
    /* Clean up */
    aws_byte_buf_clean_up(&output_buf);
    aws_byte_buf_clean_up(&output_decrypted);
    aws_pkcs11_lib_close_session(pkcs11_lib, session);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_decrypt, s_test_pkcs11_decrypt)

static int s_test_pkcs11_sign(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    CK_SLOT_ID created_slot = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    struct aws_pkcs11_lib *pkcs11_lib = NULL;
    s_setup_test(allocator, &pkcs11_lib, &created_slot, &session);
    CK_FUNCTION_LIST_PTR pkcs11_function_list = aws_pkcs11_lib_get_function_list(pkcs11_lib);

    CK_OBJECT_HANDLE created_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE created_pub_key = CK_INVALID_HANDLE;
    struct pkcs11_key_creation_params params = {
        .key_label = DEFAULT_KEY_LABEL, .key_id = DEFAULT_KEY_ID, .key_length = 2048};
    ASSERT_SUCCESS(s_pkcs11_create_key(pkcs11_function_list, &params, session, &created_key, &created_pub_key));

    struct aws_byte_cursor message_to_sign = aws_byte_cursor_from_c_str("ABCDEFGHIJKL");
    struct aws_byte_buf signature; /* initialized later */
    AWS_ZERO_STRUCT(signature);

    /* Sign a message */
    ASSERT_SUCCESS(aws_pkcs11_lib_sign(
        pkcs11_lib, session, created_key, SUPPORTED_KEY_TYPE, message_to_sign, allocator, &signature));

    /* There is no good way to validate without this, as we append this prefix internally before signing. */
    /* clang-format off */
    const uint8_t sha256_prefix[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    /* clang-format on */
    struct aws_byte_buf prefixed_input;
    aws_byte_buf_init(&prefixed_input, allocator, message_to_sign.len + sizeof(sha256_prefix));
    aws_byte_buf_write(&prefixed_input, sha256_prefix, sizeof(sha256_prefix));
    aws_byte_buf_write_from_whole_cursor(&prefixed_input, message_to_sign);
    struct aws_byte_cursor input_message_to_verify = aws_byte_cursor_from_buf(&prefixed_input);

    /* Verify the signature */
    ASSERT_SUCCESS(s_pkcs11_verify_signature(
        pkcs11_function_list, &input_message_to_verify, &signature, session, created_pub_key));

    /* Assert that sign fails for non RSA key type */
    CK_KEY_TYPE unsupported_key_type = CKK_EC;
    aws_byte_buf_clean_up(&signature);
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        pkcs11_lib, session, created_key, unsupported_key_type, message_to_sign, allocator, &signature));

    /* Invalid session handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        pkcs11_lib, CK_INVALID_HANDLE, created_key, SUPPORTED_KEY_TYPE, message_to_sign, allocator, &signature));

    /* Invalid key handle should fail */
    ASSERT_FAILS(aws_pkcs11_lib_sign(
        pkcs11_lib, session, CK_INVALID_HANDLE, SUPPORTED_KEY_TYPE, message_to_sign, allocator, &signature));

    /* Clean up */
    aws_byte_buf_clean_up(&prefixed_input);
    aws_pkcs11_lib_close_session(pkcs11_lib, session);
    s_pkcs11_clear_softhsm();
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_sign, s_test_pkcs11_sign)

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * See PKCS11.md for instructions on running these tests
 */

#include <limits.h>
#include <unistd.h>
#include <aws/io/pkcs11.h>
#include <aws/io/private/pkcs11_private.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>
#include <aws/testing/aws_test_harness.h>

AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_LIB, "TEST_PKCS11_LIB");
AWS_STATIC_STRING_FROM_LITERAL(TEST_PKCS11_TOKEN_DIR, "TEST_PKCS11_TOKEN_DIR");

extern const char *s_ckr_str(CK_RV rv);
/* Singleton that stores env-var values */
struct pkcs11_tester {
    struct aws_string *shared_lib_path;
    struct aws_string *token_dir;
};

static struct pkcs11_tester s_pkcs11_tester;
CK_SLOT_ID next_free_slot_id = 0;
const char* const TOKEN_LABEL = "label";
const char* const SO_PIN = "qwerty";
const char* const USER_PIN = "341269504732";
/*
 * Helper functions to interact with softhsm begin
 * */


/* Helper pkcs functions to provision/setup/clear softhsm tokens/keys */
static CK_SLOT_ID s_pkcs11_find_slot(struct aws_pkcs11_lib *pkcs11_lib, CK_TOKEN_INFO tokenInfo) {
    CK_ULONG ul_slot_count;
    CK_SLOT_ID slot_id = -1;
    CK_RV rv = pkcs11_lib->function_list->C_GetSlotList(CK_TRUE, NULL_PTR, &ul_slot_count);
    if (rv != CKR_OK) {
        FAIL("ERROR: Could not get the number of slots.\n");
    }

    CK_SLOT_ID_PTR p_slot_list = (CK_SLOT_ID_PTR)malloc(ul_slot_count * sizeof(CK_SLOT_ID));
    if (p_slot_list == NULL) {
        FAIL("ERROR: Could not allocate memory.\n");
    }

    rv = pkcs11_lib->function_list->C_GetSlotList(CK_FALSE, p_slot_list, &ul_slot_count);
    if (rv != CKR_OK) {
        free(p_slot_list);
        FAIL("ERROR: Could not get the slot list.\n");
    }

    size_t counter = 0;
    for (CK_ULONG i = 0; i < ul_slot_count; i++) {
        CK_TOKEN_INFO curr_token_info;

        rv = pkcs11_lib->function_list->C_GetTokenInfo(p_slot_list[i], &curr_token_info);
        if (rv != CKR_OK) {
            free(p_slot_list);
            FAIL("ERROR: Could not get info about the token in slot %lu.\n", p_slot_list[i]);
        }

        if (memcmp(curr_token_info.serialNumber, tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber)) == 0 &&
            memcmp(curr_token_info.label, tokenInfo.label, sizeof(tokenInfo.label)) == 0) {
            slot_id = p_slot_list[i];
            counter++;
        }
    }

    free(p_slot_list);

    if (counter == 1) return slot_id;
    if (counter > 1) {
        FAIL("ERROR: Found multiple matching slots/tokens.\n");
    }
    FAIL("ERROR: Could not find a slot/token using --serial, or --token\n");
}

static void s_pkcs11_clear_softhsm(struct aws_pkcs11_lib *pkcs11_lib) {
    char cmd[120] = {'\0'};
    const char* token_dir = aws_string_c_str(s_pkcs11_tester.token_dir);
    if (token_dir[s_pkcs11_tester.token_dir->len - 1] == '/') {
        sprintf(cmd, "rm -rf %s*", token_dir);
    } else {
        sprintf(cmd, "rm -rf %s/*", token_dir);
    }
    printf("Executing command: %s", cmd);
    system(cmd);
    next_free_slot_id = 0;
    // Reload the library
    pkcs11_lib->function_list->C_Finalize(NULL_PTR);
    pkcs11_lib->function_list->C_Initialize(NULL_PTR);
}

static CK_OBJECT_HANDLE s_pkcs11_create_key(struct aws_pkcs11_lib *pkcs11_lib,
                                            CK_SLOT_ID slot_id,
                                            const char* const label,
                                            const char* const id,
                                            CK_SESSION_HANDLE session) {
    CK_OBJECT_HANDLE priv_key;
    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,    (void *)label,  (CK_ULONG)strlen(label) },
        { CKA_ID,       (void *)id,     (CK_ULONG)strlen(id) }
    };
    CK_MECHANISM mech = { CKM_DES_KEY_GEN, NULL_PTR, 0};

    CK_RV rv = pkcs11_lib->function_list->C_GenerateKey(session, &mech, privateKeyTemplate, 2, &priv_key);
    if (rv != CKR_OK) {
        FAIL("C_GenerateKey fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }
    return priv_key;
}

static uint64_t s_pkcs11_softhsm_create_slot(struct aws_pkcs11_lib *pkcs11_lib,
                                        const char *const token_name,
                                        const char *const so_pin,
                                        const char *const user_pin) {
    ASSERT_NOT_NULL(pkcs11_lib);
    CK_RV rv;
    CK_SLOT_ID slot_id = next_free_slot_id;

    // API expects ' ' padded string
    CK_UTF8CHAR paddedLabel[32];
    memset(paddedLabel, ' ', sizeof(paddedLabel));
    memcpy(paddedLabel, token_name, strlen(token_name));

    rv = pkcs11_lib->function_list->C_InitToken(slot_id, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin), paddedLabel);
    if (rv != CKR_OK) {
        FAIL("C_InitToken fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }
    CK_SESSION_HANDLE hSession;
    rv = pkcs11_lib->function_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
    if (rv != CKR_OK) {
        FAIL("C_OpenSession fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }

    rv = pkcs11_lib->function_list->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin));
    if (rv != CKR_OK) {
        FAIL("C_Login fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }

    rv = pkcs11_lib->function_list->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)user_pin, strlen(user_pin));
    if (rv != CKR_OK) {
        FAIL("C_InitPIN fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }
    CK_TOKEN_INFO tokenInfo;
    rv = pkcs11_lib->function_list->C_GetTokenInfo(slot_id, &tokenInfo);
    if (rv != CKR_OK) {
        FAIL("C_GetTokenInfo fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }
    // Reload the library
    pkcs11_lib->function_list->C_Finalize(NULL_PTR);
    rv = pkcs11_lib->function_list->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        FAIL("C_Initialize fails: PKCS#11 error: %s (0x%08lX)", s_ckr_str(rv), rv);
    }

    CK_SLOT_ID new_slot_id = s_pkcs11_find_slot(pkcs11_lib, tokenInfo);
    if (slot_id == new_slot_id) {
        printf("The token has been initialized on slot %lu\n", new_slot_id);
    } else {
        printf("The token has been initialized and is reassigned to slot %lu\n", new_slot_id);
    }
    ++next_free_slot_id;
    return (uint64_t)new_slot_id;
}

/*
 * Helper functions to interact with softhsm end
 * */

static void s_pkcs11_tester_clean_up(void) {
    aws_string_destroy(s_pkcs11_tester.shared_lib_path);
    aws_string_destroy(s_pkcs11_tester.token_dir);
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

    return AWS_OP_SUCCESS;

missing:
    printf("Missing required env-var '%s'\n", aws_string_c_str(env_var));
    return aws_raise_error(AWS_ERROR_INVALID_STATE);
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

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);
    /* Always start with a clean state */
    s_pkcs11_clear_softhsm(pkcs11_lib);

    /* Try creating a session for an invalid slot */
    uint64_t session = ULONG_MAX;
    /* We havent created any slots and we are starting from a clean softhsm, so any slot value is invalid */
    uint64_t slot = 1UL;
    ASSERT_FAILS(aws_pkcs11_lib_open_session(pkcs11_lib, slot, &session /*out*/));

    /* Create a new slot */
    CK_SLOT_ID created_slot = s_pkcs11_softhsm_create_slot(pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN);
    printf("Got slot: %lu\n", created_slot);

    uint64_t first_session = ULONG_MAX;
    uint64_t second_session = ULONG_MAX;
    /* Now, creation of a session on a valid slot will be a success */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &first_session /*out*/));
    ASSERT_TRUE(first_session != ULONG_MAX);

    /* create one more session */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &second_session /*out*/));
    ASSERT_TRUE(second_session != ULONG_MAX);
    ASSERT_TRUE(first_session != second_session);

    /* Close both sessions */
    aws_pkcs11_lib_close_session(pkcs11_lib, first_session);
    aws_pkcs11_lib_close_session(pkcs11_lib, second_session);

    /* Clean up */
    s_pkcs11_clear_softhsm(pkcs11_lib);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_session_tests, s_test_pkcs11_session_tests)

static int s_test_pkcs11_login_tests(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);
    /* Always start with a clean state */
    s_pkcs11_clear_softhsm(pkcs11_lib);

    /* Create a new slot */
    CK_SLOT_ID created_slot = s_pkcs11_softhsm_create_slot(pkcs11_lib, TOKEN_LABEL, SO_PIN, USER_PIN);
    printf("Got slot: %lu\n", created_slot);

    /* Try to login with in invalid session, we have not created any session on this token
     * So, any session value is invalid */
    struct aws_string* pin = aws_string_new_from_c_str(allocator, USER_PIN);
    uint64_t invalid_session = 1UL;
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, invalid_session, pin));

    /* Now create a valid session */
    uint64_t session;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session /*out*/));

    /* Try an invalid pin on a valid slot */
    struct aws_string* invalid_pin = aws_string_new_from_c_str(allocator, "INVALID_PIN");
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, session, invalid_pin));

    /* Try a valid pin on a valid slot */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session, pin));

    /* A re login should fail, as we are already logged in now */
    ASSERT_FAILS(aws_pkcs11_lib_login_user(pkcs11_lib, session, pin));

    /* Now create one more session */
    uint64_t session_2;
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
    s_pkcs11_clear_softhsm(pkcs11_lib);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_login_tests, s_test_pkcs11_login_tests)

static int s_test_pkcs11_find_private_key(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));

    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Always start with a clean state */
    s_pkcs11_clear_softhsm(pkcs11_lib);

    /* TODO: Add support for all supported key types and lengths */
    const char* const key_label_1 = "DES_KEY";
    const char* const key_id_1 = "BEEFCAFE";
    const char* const key_label_2 = "DES_KEY_2";
    const char* const key_id_2 = "BEEFCAFEDEAD";
    const char* const label_1 = "label!@#$%^&*-_=+{}[]<>?,./():_1";
    const char* const so_pin_1 = "qwertyuioplaksjdhfgbn341269504732";
    const char* const user_pin_1 = "341269504732";

    /* Create a new slot */
    CK_SLOT_ID created_slot = s_pkcs11_softhsm_create_slot(pkcs11_lib, label_1, so_pin_1, user_pin_1);
    printf("Got slot: %lu\n", created_slot);

    /* Do not close the session while running a test, objects created by a session are cleaned up
     * when the session is closed.
     * http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc386027485
     * */
    /* Open a different session to access the created key, and a different one to create */
    uint64_t session_to_access_key;
    uint64_t session_to_create_key;
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_access_key /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key /*out*/));

    /* Login user */
    struct aws_string* user_pin = aws_string_new_from_c_str(allocator, user_pin_1);
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_to_access_key, user_pin));

    unsigned long created_key = s_pkcs11_create_key(pkcs11_lib,
                                                    created_slot,
                                                    key_label_1,
                                                    key_id_1,
                                                    session_to_create_key);

    /* Find key */
    uint64_t pkey_handle = ULONG_MAX;
    struct aws_string* key_label_str = aws_string_new_from_c_str(allocator, key_label_1);
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib,
                                        session_to_access_key,
                                        key_label_str,
                                        &pkey_handle));
    ASSERT_TRUE(pkey_handle == created_key);

    /* Since there is only one key, a lookup without label should also return the key */
    pkey_handle = ULONG_MAX;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib,
                                        session_to_access_key,
                                        NULL,
                                        &pkey_handle));
    ASSERT_TRUE(pkey_handle == created_key);

    /* Close both sessions for a clean setup again */
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_access_key);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key);

    uint64_t session_to_create_key_1;
    uint64_t session_to_create_key_2;

    /* Open a session to access the created key */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_access_key /*out*/));
    /* Open sessions to create keys */
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key_1 /*out*/));
    ASSERT_SUCCESS(aws_pkcs11_lib_open_session(pkcs11_lib, created_slot, &session_to_create_key_2 /*out*/));

    /* Login user */
    ASSERT_SUCCESS(aws_pkcs11_lib_login_user(pkcs11_lib, session_to_access_key, user_pin));

    unsigned long created_key_1 = s_pkcs11_create_key(pkcs11_lib,
                                                      created_slot,
                                                      key_label_1,
                                                      key_id_1,
                                                      session_to_create_key_1);
    unsigned long created_key_2 = s_pkcs11_create_key(pkcs11_lib,
                                                      created_slot,
                                                      key_label_2,
                                                      key_id_2,
                                                      session_to_create_key_2);

    /* Since there are 2 keys, a lookup without label should fail */
    struct aws_string* key_label_2_str = aws_string_new_from_c_str(allocator, key_label_2);
    pkey_handle = ULONG_MAX;
    ASSERT_FAILS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib,
                                        session_to_access_key,
                                        NULL,
                                        &pkey_handle));

    /* a lookup with label for the first key should find the first key */
    pkey_handle = ULONG_MAX;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib,
                                        session_to_access_key,
                                        key_label_str,
                                        &pkey_handle));
    ASSERT_TRUE(pkey_handle == created_key_1);

    /* a lookup with label for the second key should find the second key */
    pkey_handle = ULONG_MAX;
    ASSERT_SUCCESS(
        aws_pkcs11_lib_find_private_key(pkcs11_lib,
                                        session_to_access_key,
                                        key_label_2_str,
                                        &pkey_handle));
    ASSERT_TRUE(pkey_handle == created_key_2);

    /* Clean up */
    aws_string_destroy(key_label_str);
    aws_string_destroy(key_label_2_str);
    aws_string_destroy(user_pin);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_access_key);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key_1);
    aws_pkcs11_lib_close_session(pkcs11_lib, session_to_create_key_2);
    s_pkcs11_clear_softhsm(pkcs11_lib);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_private_key, s_test_pkcs11_find_private_key)

static int s_test_pkcs11_find_slot(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(s_pkcs11_tester_init(allocator));
    /* Load library */
    struct aws_pkcs11_lib_options options = {
        .filename = aws_byte_cursor_from_string(s_pkcs11_tester.shared_lib_path),
    };
    struct aws_pkcs11_lib *pkcs11_lib = aws_pkcs11_lib_new(allocator, &options);
    ASSERT_NOT_NULL(pkcs11_lib);

    /* Always start with a clean state */
    s_pkcs11_clear_softhsm(pkcs11_lib);

    /* softhsm does not like ;| as part of label */
    const char* const label_1 = "label!@#$%^&*-_=+{}[]<>?,./():_1";
    const char* const label_2 = "label!@#$%^&*()_2";
    const char* const label_3 = "label!@#$%^&*()_3";

    const char* const so_pin_1 = "qwertyuioplaksjdhfgbn341269504732";
    const char* const so_pin_2 = "ABCD";
    const char* const so_pin_3 = "0111";

    const char* const user_pin_1 = "341269504732";
    const char* const user_pin_2 = "ABCD";
    const char* const user_pin_3 = "0111";

    uint64_t slot_id = ULONG_LONG_MAX;
    /*
     * Softhsm always has one uninitialized token which is returned by the GetSlotList() API,
     * so there is no way to start without any slot at all
     * */

    /* Call aws_pkcs11_lib_find_slot_with_token with 1 token, but no matching criteria */
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, NULL /*match_slot_id*/, NULL, &slot_id /*out*/));
    ASSERT_TRUE(slot_id == next_free_slot_id);

    /* Create a new slot */
    uint64_t created_slot = s_pkcs11_softhsm_create_slot(pkcs11_lib, label_1, so_pin_1, user_pin_1);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but no matching criteria */
    slot_id = ULONG_LONG_MAX;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, NULL /*match_slot_id*/, NULL, &slot_id /*out*/));
    ASSERT_TRUE(slot_id == ULONG_LONG_MAX);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but match the slot this time */
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib, &created_slot /*match_slot_id*/, NULL, &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot);

    /* Call aws_pkcs11_lib_find_slot_with_token with 2 tokens, but match the label this time */
    slot_id = ULONG_LONG_MAX;
    struct aws_string *match_label = aws_string_new_from_c_str(allocator, label_1);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       NULL /*match_slot_id*/,
                                                       match_label,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot);

    /* clear softhsm and make sure that no tokens match with previous slot/label */
    s_pkcs11_clear_softhsm(pkcs11_lib);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the free token,
     * and assert that previous slot id does not match anymore
     * */
    slot_id = ULONG_LONG_MAX;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                     &created_slot /*match_slot_id*/,
                                                     NULL /*match_token_label*/,
                                                     &slot_id /*out*/));
    ASSERT_TRUE(slot_id == ULONG_LONG_MAX);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with just the uninitialized token,
     * and assert that previous label does not match anymore
     * */
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       NULL /*match_slot_id*/,
                                                       match_label /*match_token_label*/,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == ULONG_LONG_MAX);

    /* Create 2 new slots */
    uint64_t created_slot_1 = s_pkcs11_softhsm_create_slot(pkcs11_lib, label_2, so_pin_2, user_pin_2);
    uint64_t created_slot_2 = s_pkcs11_softhsm_create_slot(pkcs11_lib, label_3, so_pin_3, user_pin_3);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens on softhsm, but no matching criteria */
    slot_id = ULONG_LONG_MAX;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                     NULL /*match_slot_id*/,
                                                     NULL /*match_token_label*/,
                                                     &slot_id /*out*/));
    ASSERT_TRUE(slot_id == ULONG_LONG_MAX);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the slot 1 this time */
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       &created_slot_1 /*match_slot_id*/,
                                                       NULL /*match_token_label*/,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot_1);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the slot 2 this time */
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       &created_slot_2 /*match_slot_id*/,
                                                       NULL /*match_token_label*/,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot_2);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the label 1 this time */
    slot_id = ULONG_LONG_MAX;
    struct aws_string *match_label_1 = aws_string_new_from_c_str(allocator, label_2);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       NULL /*match_slot_id*/,
                                                       match_label_1 /*match_token_label*/,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot_1);

    /* Call aws_pkcs11_lib_find_slot_with_token with 3 tokens, but match the label 2 this time */
    slot_id = ULONG_LONG_MAX;
    struct aws_string *match_label_2 = aws_string_new_from_c_str(allocator, label_3);
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       NULL /*match_slot_id*/,
                                                       match_label_2 /*match_token_label*/,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot_2);

    /*
     * Call aws_pkcs11_lib_find_slot_with_token with 3 tokens,
     * but a mismatch for a slot and label should return error
     * */
    slot_id = ULONG_LONG_MAX;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                       &created_slot_1 /*match_slot_id*/,
                                                       match_label_2 /*match_token_label*/,
                                                       &slot_id /*out*/));
    ASSERT_TRUE(slot_id == ULONG_LONG_MAX);

    slot_id = ULONG_LONG_MAX;
    ASSERT_FAILS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                     &created_slot_2 /*match_slot_id*/,
                                                     match_label_1 /*match_token_label*/,
                                                     &slot_id /*out*/));
    ASSERT_TRUE(slot_id == ULONG_LONG_MAX);
    /*
     * Call aws_pkcs11_lib_find_slot_with_token with 3 tokens,
     * but match for both, slot and label should return success
     * */
    slot_id = ULONG_LONG_MAX;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                     &created_slot_1 /*match_slot_id*/,
                                                     match_label_1 /*match_token_label*/,
                                                     &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot_1);

    slot_id = ULONG_LONG_MAX;
    ASSERT_SUCCESS(aws_pkcs11_lib_find_slot_with_token(pkcs11_lib,
                                                     &created_slot_2 /*match_slot_id*/,
                                                     match_label_2 /*match_token_label*/,
                                                     &slot_id /*out*/));
    ASSERT_TRUE(slot_id == created_slot_2);

    /* Clean up */
    aws_string_destroy(match_label);
    aws_string_destroy(match_label_1);
    aws_string_destroy(match_label_2);
    s_pkcs11_clear_softhsm(pkcs11_lib);
    aws_pkcs11_lib_release(pkcs11_lib);
    s_pkcs11_tester_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(pkcs11_find_slot, s_test_pkcs11_find_slot)
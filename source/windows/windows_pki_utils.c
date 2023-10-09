/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/pem.h>
#include <aws/io/private/pki_utils.h>

#include <aws/common/uuid.h>

#include <aws/io/logging.h>

#include <Windows.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define CERT_HASH_STR_LEN 40
#define CERT_HASH_LEN 20

/**
 * Split system cert path into exactly three segments like:
 * "CurrentUser\My\a11f8a9b5df5b98ba3508fbca575d09570e0d2c6"
 *      -> ["CurrentUser", "My", "a11f8a9b5df5b98ba3508fbca575d09570e0d2c6"]
 */
static int s_split_system_cert_path(const char *cert_path, struct aws_byte_cursor out_splits[3]) {

    struct aws_byte_cursor cert_path_cursor = aws_byte_cursor_from_c_str(cert_path);

    struct aws_byte_cursor segment;
    AWS_ZERO_STRUCT(segment);

    for (size_t i = 0; i < 3; ++i) {
        if (!aws_byte_cursor_next_split(&cert_path_cursor, '\\', &segment)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: invalid certificate path '%s'. Expected additional '\\' separator.", cert_path);
            return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
        }

        out_splits[i] = segment;
    }

    if (aws_byte_cursor_next_split(&cert_path_cursor, '\\', &segment)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: invalid certificate path '%s'. Too many '\\' separators found.", cert_path);
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    return AWS_OP_SUCCESS;
}

int aws_load_cert_from_system_cert_store(const char *cert_path, HCERTSTORE *cert_store, PCCERT_CONTEXT *certs) {

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: loading certificate at windows cert manager path '%s'.", cert_path);

    struct aws_byte_cursor segments[3];
    if (s_split_system_cert_path(cert_path, segments)) {
        return AWS_OP_ERR;
    }
    const struct aws_byte_cursor store_location = segments[0];
    const struct aws_byte_cursor store_path_cursor = segments[1];
    const struct aws_byte_cursor cert_hash_cursor = segments[2];

    DWORD store_val = 0;
    if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "CurrentUser")) {
        store_val = CERT_SYSTEM_STORE_CURRENT_USER;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "LocalMachine")) {
        store_val = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "CurrentService")) {
        store_val = CERT_SYSTEM_STORE_CURRENT_SERVICE;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "Services")) {
        store_val = CERT_SYSTEM_STORE_SERVICES;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "Users")) {
        store_val = CERT_SYSTEM_STORE_USERS;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "CurrentUserGroupPolicy")) {
        store_val = CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "LocalMachineGroupPolicy")) {
        store_val = CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
    } else if (aws_byte_cursor_eq_c_str_ignore_case(&store_location, "LocalMachineEnterprise")) {
        store_val = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path '%s'. System store location '" PRInSTR "' not recognized."
            " Expected something like 'CurrentUser'.",
            cert_path,
            AWS_BYTE_CURSOR_PRI(store_location));

        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_PKI, "static: determined registry value for lookup as %d.", (int)store_val);

    /* The store_val value has to be only the path segment related to the physical store. Looking
       at the docs, 128 bytes should be plenty to store that segment.
       https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/system-store-locations */
    char store_path[128] = {0};
    if (store_path_cursor.len >= sizeof(store_path)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate path '%s'. Store name is too long.", cert_path);
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }
    memcpy(store_path, store_path_cursor.ptr, store_path_cursor.len);

    if (cert_hash_cursor.len != CERT_HASH_STR_LEN) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path '%s'. '" PRInSTR "' should have been"
            " 40 bytes of hex encoded data",
            cert_path,
            AWS_BYTE_CURSOR_PRI(cert_hash_cursor));
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    *cert_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV)NULL, CERT_STORE_OPEN_EXISTING_FLAG | store_val, store_path);

    if (!*cert_store) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path '%s'. Failed to load cert store with error code %d",
            cert_path,
            (int)GetLastError());
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    BYTE cert_hash_data[CERT_HASH_LEN];
    CRYPT_HASH_BLOB cert_hash = {
        .pbData = cert_hash_data,
        .cbData = CERT_HASH_LEN,
    };

    if (!CryptStringToBinaryA(
            (LPCSTR)cert_hash_cursor.ptr, /* this is null-terminated, it's the last segment of c-str */
            CERT_HASH_STR_LEN,
            CRYPT_STRING_HEX,
            cert_hash.pbData,
            &cert_hash.cbData,
            NULL,
            NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path '%s'. '" PRInSTR "' should have been a hex encoded string",
            cert_path,
            AWS_BYTE_CURSOR_PRI(cert_hash_cursor));
        aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
        goto on_error;
    }

    *certs = CertFindCertificateInStore(
        *cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &cert_hash, NULL);

    if (!*certs) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path '%s'. "
            "The referenced certificate was not found in the certificate store, error code %d",
            cert_path,
            (int)GetLastError());
        aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
        goto on_error;
    }

    return AWS_OP_SUCCESS;

on_error:

    if (*cert_store != NULL) {
        aws_close_cert_store(*cert_store);
        *cert_store = NULL;
    }

    return AWS_OP_ERR;
}

int aws_import_trusted_certificates(
    struct aws_allocator *alloc,
    const struct aws_byte_cursor *certificates_blob,
    HCERTSTORE *cert_store) {
    struct aws_array_list certificates;
    *cert_store = NULL;
    int result = AWS_OP_ERR;

    if (aws_pem_objects_init_from_file_contents(&certificates, alloc, *certificates_blob)) {
        goto clean_up;
    }

    size_t cert_count = aws_array_list_length(&certificates);
    if (cert_count == 0) {
        aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: no certificates found, error %s", aws_error_name(aws_last_error()));
        goto clean_up;
    }

    HCERTSTORE tmp_cert_store =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);
    *cert_store = tmp_cert_store;
    if (!*cert_store) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: failed to create temporary cert store, error code %d", (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up;
    }

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: loading %d certificates in cert chain for use as a CA", (int)cert_count);
    for (size_t i = 0; i < cert_count; ++i) {
        struct aws_pem_object *pem_object_ptr = NULL;
        aws_array_list_get_at_ptr(&certificates, (void **)&pem_object_ptr, i);

        CERT_BLOB cert_blob;
        CERT_CONTEXT *cert_context = NULL;

        cert_blob.pbData = pem_object_ptr->data.buffer;
        cert_blob.cbData = (DWORD)pem_object_ptr->data.len;

        DWORD content_type = 0;
        BOOL query_res = CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &cert_blob,
            CERT_QUERY_CONTENT_FLAG_CERT,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            NULL,
            &content_type,
            NULL,
            NULL,
            NULL,
            (const void **)&cert_context);

        if (!query_res || cert_context == NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: failed to parse certificate blob, error code %d", (int)GetLastError());
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        BOOL add_result = CertAddCertificateContextToStore(*cert_store, cert_context, CERT_STORE_ADD_ALWAYS, NULL);
        if (!add_result) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: failed to add certificate to store, error code %d", (int)GetLastError());
        }

        CertFreeCertificateContext(cert_context);

        if (!add_result) {
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto clean_up;
        }
    }

    result = AWS_OP_SUCCESS;

clean_up:

    aws_pem_objects_clean_up(&certificates);

    if (result == AWS_OP_ERR && *cert_store) {
        aws_close_cert_store(*cert_store);
        *cert_store = NULL;
    }

    return result;
}

void aws_close_cert_store(HCERTSTORE cert_store) {
    CertCloseStore(cert_store, 0);
}

static int s_cert_context_import_rsa_private_key(
    PCCERT_CONTEXT certs,
    const BYTE *key,
    DWORD decoded_len,
    bool is_client_mode,
    wchar_t uuid_wstr[AWS_UUID_STR_LEN],
    HCRYPTPROV *out_crypto_provider,
    HCRYPTKEY *out_private_key_handle) {

    /* out-params will adopt these resources if the function is successful.
     * if function fails these resources will be cleaned up before returning */
    HCRYPTPROV crypto_prov = 0;
    HCRYPTKEY h_key = 0;

    if (is_client_mode) {
        /* use CRYPT_VERIFYCONTEXT so that keys are ephemeral (not stored to disk, registry, etc) */
        if (!CryptAcquireContextW(&crypto_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI,
                "static: error creating a new rsa crypto context for key with errno %d",
                (int)GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto on_error;
        }

        if (!CryptImportKey(crypto_prov, key, decoded_len, 0, 0, &h_key)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: failed to import rsa key into crypto provider, error code %d", GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto on_error;
        }

        if (!CertSetCertificateContextProperty(certs, CERT_KEY_PROV_HANDLE_PROP_ID, 0, (void *)crypto_prov)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI,
                "static: error creating a new certificate context for rsa key with errno %d",
                (int)GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto on_error;
        }
    } else {
        if (!CryptAcquireContextW(&crypto_prov, uuid_wstr, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: error creating a new rsa crypto context with errno %d", (int)GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto on_error;
        }

        if (!CryptImportKey(crypto_prov, key, decoded_len, 0, 0, &h_key)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: failed to import rsa key into crypto provider, error code %d", GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto on_error;
        }

        CRYPT_KEY_PROV_INFO key_prov_info;
        AWS_ZERO_STRUCT(key_prov_info);
        key_prov_info.pwszContainerName = uuid_wstr;
        key_prov_info.dwProvType = PROV_RSA_FULL;
        key_prov_info.dwKeySpec = AT_KEYEXCHANGE;

        if (!CertSetCertificateContextProperty(certs, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI,
                "static: error creating a new certificate context for key with errno %d",
                (int)GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto on_error;
        }
    }

    *out_crypto_provider = crypto_prov;
    *out_private_key_handle = h_key;
    return AWS_OP_SUCCESS;

on_error:

    if (h_key != 0) {
        CryptDestroyKey(h_key);
    }

    if (crypto_prov != 0) {
        CryptReleaseContext(crypto_prov, 0);
    }

    return AWS_OP_ERR;
}

#define ECC_256_MAGIC_NUMBER 0x20
#define ECC_384_MAGIC_NUMBER 0x30

static ULONG s_compute_ecc_key_type_from_private_key_size(size_t private_key_len) {
    switch (private_key_len) {
        case ECC_256_MAGIC_NUMBER:
            return BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        case ECC_384_MAGIC_NUMBER:
            return BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        default:
            return BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
    }
}

#ifndef AWS_SUPPORT_WIN7

enum aws_ecc_public_key_compression_type {
    AWS_EPKCT_COMPRESSED_EVEN = 0x02,
    AWS_EPKCT_COMPRESSED_ODD = 0x03,
    AWS_EPKCT_UNCOMPRESSED = 0x04,
};

/* TODO ALSO NEEDS TO BE EPHEMERAL */
static int s_cert_context_import_ecc_private_key(
    PCCERT_CONTEXT cert_context,
    struct aws_allocator *allocator,
    const BYTE *key,
    DWORD decoded_len,
    wchar_t uuid_wstr[AWS_UUID_STR_LEN]) {

    (void)decoded_len;

    AWS_FATAL_ASSERT(cert_context != NULL);

    NCRYPT_PROV_HANDLE crypto_prov = 0;
    NCRYPT_KEY_HANDLE h_key = 0;
    BCRYPT_ECCKEY_BLOB *key_blob = NULL;
    int result = AWS_OP_ERR;
    SECURITY_STATUS status;

    CRYPT_BIT_BLOB *public_key_blob = &cert_context->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    DWORD public_key_blob_length = public_key_blob->cbData;
    if (public_key_blob_length == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid zero-length ecc key data");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    /*
     * Per rfc5480#section-2.2, the public key section of the encoding consists of a single byte that tells whether or
     * not the public key is compressed, followed by the raw key data itself.  Windows doesn't seem to support importing
     * compressed keys directly, so for now check and fail if it's a compressed key.
     *
     * Given that we're pulling the data from a windows internal structure generated by CryptQueryObject, it is
     * not known whether it's even possible to see a compressed tag here or if Windows automatically uncompresses a
     * compressed key for you.  The win32 documentation is quite unhelpful here.
     *
     * We could test this by generating a certificate that contains a compressed public key and feeding it in.
     * I cannot find a way to do it that doesn't involve raw hex editing a sub object in the DER encoding of the
     * certificate. So figuring out the final expectation here is a TODO.
     */
    if (*public_key_blob->pbData != AWS_EPKCT_UNCOMPRESSED) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: compressed ecc public keys not yet supported.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    /*
     * Now we want everything but the first byte, so dec the length and bump the pointer.  I was more comfortable doing
     * it the manual way rather than with cursors because using cursors would force us to do multiple narrowing casts
     * back when configuring win32 data.
     */
    public_key_blob_length--;
    struct aws_byte_cursor public_blob_cursor = {
        .ptr = public_key_blob->pbData + 1,
        .len = public_key_blob_length,
    };

    CRYPT_ECC_PRIVATE_KEY_INFO *private_key_info = (CRYPT_ECC_PRIVATE_KEY_INFO *)key;
    ULONG private_key_length = private_key_info->PrivateKey.cbData;
    struct aws_byte_cursor private_key_cursor = {
        .ptr = private_key_info->PrivateKey.pbData,
        .len = private_key_length,
    };

    DWORD key_blob_size = sizeof(BCRYPT_ECCKEY_BLOB) + public_key_blob_length + private_key_length;
    key_blob = (BCRYPT_ECCKEY_BLOB *)aws_mem_calloc(allocator, 1, key_blob_size);
    if (key_blob == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: could not allocate ecc key blob memory");
        goto done;
    }

    key_blob->dwMagic = s_compute_ecc_key_type_from_private_key_size(private_key_cursor.len);
    key_blob->cbKey = private_key_length;

    struct aws_byte_buf key_blob_buffer = {
        .buffer = (uint8_t *)key_blob,
        .len = sizeof(BCRYPT_ECCKEY_BLOB),
        .capacity = key_blob_size,
    };

    if (aws_byte_buf_append(&key_blob_buffer, &public_blob_cursor)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: insufficient space to build ecc key blob");
        goto done;
    }

    if (aws_byte_buf_append(&key_blob_buffer, &private_key_cursor)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: insufficient space to build ecc key blob");
        goto done;
    }

    status = NCryptOpenStorageProvider(&crypto_prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: could not open ncrypt key storage provider, error %d", (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    NCryptBuffer ncBuf = {AWS_UUID_STR_LEN * sizeof(wchar_t), NCRYPTBUFFER_PKCS_KEY_NAME, uuid_wstr};
    NCryptBufferDesc ncBufDesc;
    ncBufDesc.ulVersion = 0;
    ncBufDesc.cBuffers = 1;
    ncBufDesc.pBuffers = &ncBuf;

    status = NCryptImportKey(
        crypto_prov,
        0,
        BCRYPT_ECCPRIVATE_BLOB,
        &ncBufDesc,
        &h_key,
        (BYTE *)key_blob,
        key_blob_size,
        NCRYPT_OVERWRITE_KEY_FLAG);

    if (status != ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: failed to import ecc key with status %d, last error %d",
            status,
            (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    CRYPT_KEY_PROV_INFO key_prov_info = {uuid_wstr, MS_KEY_STORAGE_PROVIDER, 0, 0, 0, NULL, 0};

    if (!CertSetCertificateContextProperty(cert_context, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: failed to set cert context key provider, with last error %d", (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    if (h_key != 0) {
        NCryptFreeObject(h_key);
    }

    if (crypto_prov != 0) {
        NCryptFreeObject(crypto_prov);
    }

    if (key_blob != NULL) {
        aws_mem_release(allocator, key_blob);
    }

    return result;
}

#endif /* AWS_SUPPORT_WIN7 */

enum aws_certificate_type {
    AWS_CT_X509_UNKNOWN,
    AWS_CT_X509_RSA,
    AWS_CT_X509_ECC,
};

int aws_import_key_pair_to_cert_context(
    struct aws_allocator *alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    bool is_client_mode,
    HCERTSTORE *store,
    PCCERT_CONTEXT *certs,
    HCRYPTPROV *crypto_provider,
    HCRYPTKEY *private_key_handle) {

    struct aws_array_list certificates, private_keys;
    AWS_ZERO_STRUCT(certificates);
    AWS_ZERO_STRUCT(private_keys);

    *certs = NULL;
    *store = NULL;
    *crypto_provider = 0;
    *private_key_handle = 0;

    int result = AWS_OP_ERR;
    BYTE *key = NULL;

    if (aws_pem_objects_init_from_file_contents(&certificates, alloc, *public_cert_chain)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: failed to decode cert pem to buffer list with error %d", (int)aws_last_error());
        goto clean_up;
    }

    if (aws_pem_objects_init_from_file_contents(&private_keys, alloc, *private_key)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: failed to decode key pem to buffer list with error %d", (int)aws_last_error());
        goto clean_up;
    }

    size_t cert_count = aws_array_list_length(&certificates);
    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: loading certificate chain with %d certificates.", (int)cert_count);
    *store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);

    if (!*store) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: failed to load in-memory/ephemeral certificate store, error code %d",
            GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up;
    }

    for (size_t i = 0; i < cert_count; ++i) {
        struct aws_pem_object *pem_object_ptr = NULL;
        aws_array_list_get_at_ptr(&certificates, (void **)&pem_object_ptr, i);

        CERT_BLOB cert_blob;

        cert_blob.pbData = pem_object_ptr->data.buffer;
        cert_blob.cbData = (DWORD)pem_object_ptr->data.len;

        DWORD content_type = 0;
        PCERT_CONTEXT cert_context = NULL;
        BOOL query_res = CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &cert_blob,
            CERT_QUERY_CONTENT_FLAG_CERT,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            NULL,
            &content_type,
            NULL,
            NULL,
            NULL,
            (const void **)&cert_context);

        if (!query_res || cert_context == NULL) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate blob, error code %d.", GetLastError());
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        BOOL add_result = CertAddCertificateContextToStore(*store, cert_context, CERT_STORE_ADD_ALWAYS, NULL);
        if (!add_result) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: unable to add , error code %d.", GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }

        if (i != 0 || !add_result) {
            CertFreeCertificateContext(cert_context);
        } else {
            *certs = cert_context;
        }

        if (!add_result) {
            goto clean_up;
        }
    }

    if (*certs == NULL) {
        aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: no certificates found, error %s", aws_error_name(aws_last_error()));
        goto clean_up;
    }

    struct aws_pem_object *private_key_ptr = NULL;
    DWORD decoded_len = 0;
    enum aws_certificate_type cert_type = AWS_CT_X509_UNKNOWN;
    size_t private_key_count = aws_array_list_length(&private_keys);
    for (size_t i = 0; i < private_key_count; ++i) {
        aws_array_list_get_at_ptr(&private_keys, (void **)&private_key_ptr, i);

        if (CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                PKCS_RSA_PRIVATE_KEY,
                private_key_ptr->data.buffer,
                (DWORD)private_key_ptr->data.len,
                CRYPT_DECODE_ALLOC_FLAG,
                0,
                &key,
                &decoded_len)) {
            cert_type = AWS_CT_X509_RSA;
        }
#ifndef AWS_SUPPORT_WIN7
        else if (CryptDecodeObjectEx(
                     X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                     X509_ECC_PRIVATE_KEY,
                     private_key_ptr->data.buffer,
                     (DWORD)private_key_ptr->data.len,
                     CRYPT_DECODE_ALLOC_FLAG,
                     NULL,
                     &key,
                     &decoded_len)) {
            cert_type = AWS_CT_X509_ECC;
        }
#endif /* AWS_SUPPORT_WIN7 */

        if (cert_type != AWS_CT_X509_UNKNOWN) {
            break;
        }
    }

    if (cert_type == AWS_CT_X509_UNKNOWN) {
        aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: no acceptable private key found, error %s", aws_error_name(aws_last_error()));
        goto clean_up;
    }

    struct aws_uuid uuid;
    if (aws_uuid_init(&uuid)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to create a uuid.");
        goto clean_up;
    }

    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_str, sizeof(uuid_str));
    uuid_buf.len = 0;
    aws_uuid_to_str(&uuid, &uuid_buf);

    wchar_t uuid_wstr[AWS_UUID_STR_LEN] = {0};
    size_t converted_chars = 0;
    mbstowcs_s(&converted_chars, uuid_wstr, AWS_UUID_STR_LEN, uuid_str, sizeof(uuid_str));
    (void)converted_chars;

    switch (cert_type) {
        case AWS_CT_X509_RSA:
            result = s_cert_context_import_rsa_private_key(
                *certs, key, decoded_len, is_client_mode, uuid_wstr, crypto_provider, private_key_handle);
            break;

#ifndef AWS_SUPPORT_WIN7
        case AWS_CT_X509_ECC:
            result = s_cert_context_import_ecc_private_key(*certs, alloc, key, decoded_len, uuid_wstr);
            break;
#endif /* AWS_SUPPORT_WIN7 */

        default:
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to decode private key");
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
    }

clean_up:
    aws_pem_objects_clean_up(&certificates);
    aws_pem_objects_clean_up(&private_keys);

    LocalFree(key);

    if (result == AWS_OP_ERR) {
        if (*store != NULL) {
            aws_close_cert_store(*store);
            *store = NULL;
        }

        if (*certs) {
            CertFreeCertificateContext(*certs);
            *certs = NULL;
        }

        if (*crypto_provider != 0) {
            CryptReleaseContext(*crypto_provider, 0);
            *crypto_provider = 0;
        }

        if (*private_key_handle != 0) {
            CryptDestroyKey(*private_key_handle);
            *private_key_handle = 0;
        }
    }

    return result;
}

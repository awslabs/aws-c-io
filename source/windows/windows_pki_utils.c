/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/pki_utils.h>

#include <aws/common/uuid.h>

#include <aws/io/logging.h>

#include <Windows.h>
#include <stdio.h>
#include <string.h>

#if _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define CERT_HASH_STR_LEN 40
#define CERT_HASH_LEN 20

int aws_load_cert_from_system_cert_store(const char *cert_path, HCERTSTORE *cert_store, PCCERT_CONTEXT *certs) {

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: loading certificate at windows cert manager path %s.", cert_path);
    char *location_of_next_segment = strchr(cert_path, '\\');

    if (!location_of_next_segment) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate path %s.", cert_path);
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    size_t store_name_len = location_of_next_segment - cert_path;
    DWORD store_val = 0;

    if (!strncmp(cert_path, "CurrentUser", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_CURRENT_USER;
    } else if (!strncmp(cert_path, "LocalMachine", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    } else if (!strncmp(cert_path, "CurrentService", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_CURRENT_SERVICE;
    } else if (!strncmp(cert_path, "Services", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_SERVICES;
    } else if (!strncmp(cert_path, "Users", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_USERS;
    } else if (!strncmp(cert_path, "CurrentUserGroupPolicy", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
    } else if (!strncmp(cert_path, "LocalMachineGroupPolicy", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
    } else if (!strncmp(cert_path, "LocalMachineEnterprise", store_name_len)) {
        store_val = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: certificate path %s does not contain a valid cert store identifier.", cert_path);
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_PKI, "static: determined registry value for lookup as %d.", (int)store_val);
    location_of_next_segment += 1;
    char *store_path_start = location_of_next_segment;
    location_of_next_segment = strchr(location_of_next_segment, '\\');

    if (!location_of_next_segment) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate path %s.", cert_path);
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    /* The store_val value has to be only the path segment related to the physical store. Looking
       at the docs, 128 bytes should be plenty to store that segment.
       https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/system-store-locations */
    char store_path[128] = {0};
    AWS_FATAL_ASSERT(location_of_next_segment - store_path_start < sizeof(store_path));
    memcpy(store_path, store_path_start, location_of_next_segment - store_path_start);

    location_of_next_segment += 1;
    if (strlen(location_of_next_segment) != CERT_HASH_STR_LEN) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path %s. %s should have been"
            " 40 bytes of hex encoded data",
            cert_path,
            location_of_next_segment);
        return aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
    }

    *cert_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV)NULL, CERT_STORE_OPEN_EXISTING_FLAG | store_val, store_path);

    if (!*cert_store) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path %s. Failed to load cert store with error code %d",
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
            location_of_next_segment,
            CERT_HASH_STR_LEN,
            CRYPT_STRING_HEX,
            cert_hash.pbData,
            &cert_hash.cbData,
            NULL,
            NULL)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path %s. %s should have been a hex encoded string",
            cert_path,
            location_of_next_segment);
        aws_raise_error(AWS_ERROR_FILE_INVALID_PATH);
        goto on_error;
    }

    *certs = CertFindCertificateInStore(
        *cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &cert_hash, NULL);

    if (!*certs) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path %s. "
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

    if (aws_array_list_init_dynamic(&certificates, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, certificates_blob, &certificates)) {
        goto clean_up;
    }

    size_t cert_count = aws_array_list_length(&certificates);

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
        struct aws_byte_buf *byte_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&certificates, (void **)&byte_buf_ptr, i);

        CERT_BLOB cert_blob;
        CERT_CONTEXT *cert_context = NULL;

        cert_blob.pbData = byte_buf_ptr->buffer;
        cert_blob.cbData = (DWORD)byte_buf_ptr->len;

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

    aws_cert_chain_clean_up(&certificates);
    aws_array_list_clean_up(&certificates);

    if (result == AWS_OP_ERR && *cert_store) {
        *cert_store = NULL;
        aws_close_cert_store(*cert_store);
    }

    return result;
}

void aws_close_cert_store(HCERTSTORE cert_store) {
    CertCloseStore(cert_store, 0);
}

static int s_cert_context_import_rsa_private_key(
    PCCERT_CONTEXT *certs,
    BYTE *key,
    DWORD decoded_len,
    char uuid_str[AWS_UUID_STR_LEN]) {

    int result = AWS_OP_ERR;
    HCRYPTPROV crypto_prov = 0;
    HCRYPTKEY h_key = 0;

    wchar_t uuid_wstr[AWS_UUID_STR_LEN] = {0};
    size_t converted_chars = 0;
    mbstowcs_s(&converted_chars, uuid_wstr, AWS_UUID_STR_LEN, uuid_str, sizeof(uuid_str));
    (void)converted_chars;

    if (!CryptAcquireContextW(&crypto_prov, uuid_wstr, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: error creating a new rsa crypto context for key %s with errno %d",
            uuid_str,
            (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    if (!CryptImportKey(crypto_prov, key, decoded_len, 0, 0, &h_key)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: failed to import rsa key %s into crypto provider, error code %d",
            uuid_str,
            GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    CRYPT_KEY_PROV_INFO key_prov_info;
    AWS_ZERO_STRUCT(key_prov_info);
    key_prov_info.pwszContainerName = uuid_wstr;
    key_prov_info.dwProvType = PROV_RSA_FULL;
    key_prov_info.dwKeySpec = AT_KEYEXCHANGE;

    if (!CertSetCertificateContextProperty(*certs, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: error creating a new certificate context for key %s with errno %d",
            uuid_str,
            (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    if (h_key != 0) {
        CryptDestroyKey(h_key);
    }

    if (crypto_prov != 0) {
        CryptReleaseContext(crypto_prov, 0);
    }

    return result;
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

static int s_cert_context_import_ecc_private_key(
    PCCERT_CONTEXT *certs,
    struct aws_allocator *allocator,
    BYTE *key,
    DWORD decoded_len,
    char uuid_str[AWS_UUID_STR_LEN]) {

    (void)decoded_len;

    AWS_FATAL_ASSERT(certs != NULL);
    const CERT_CONTEXT *cert_context = *certs;
    AWS_FATAL_ASSERT(cert_context != NULL);

    HCRYPTPROV crypto_prov = 0;
    HCRYPTKEY h_key = 0;
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

    wchar_t uuid_wstr[AWS_UUID_STR_LEN] = {0};
    size_t converted_chars = 0;
    mbstowcs_s(&converted_chars, uuid_wstr, AWS_UUID_STR_LEN, uuid_str, sizeof(uuid_str));
    (void)converted_chars;

    NCryptBuffer ncBuf = {sizeof(uuid_wstr), NCRYPTBUFFER_PKCS_KEY_NAME, uuid_wstr};
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
            "static: failed to import ecc key %s with status %d, last error %d",
            uuid_str,
            status,
            (int)GetLastError());
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    CRYPT_KEY_PROV_INFO key_prov_info = {uuid_wstr, MS_KEY_STORAGE_PROVIDER, 0, 0, 0, NULL, 0};

    if (!CertSetCertificateContextProperty(cert_context, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: failed to set cert context key provider, key %s, with last error %d",
            uuid_str,
            (int)GetLastError());
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
    HCERTSTORE *store,
    PCCERT_CONTEXT *certs) {

    struct aws_array_list certificates, private_keys;
    AWS_ZERO_STRUCT(certificates);
    AWS_ZERO_STRUCT(private_keys);

    *certs = NULL;
    *store = NULL;
    int result = AWS_OP_ERR;
    CERT_CONTEXT *cert_context = NULL;
    BYTE *key = NULL;

    if (aws_array_list_init_dynamic(&certificates, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, public_cert_chain, &certificates)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "static: failed to decode cert pem to buffer list with error %d", (int)aws_last_error());
        goto clean_up;
    }

    if (aws_array_list_init_dynamic(&private_keys, alloc, 1, sizeof(struct aws_byte_buf))) {
        goto clean_up;
    }

    if (aws_decode_pem_to_buffer_list(alloc, private_key, &private_keys)) {
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
        struct aws_byte_buf *byte_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&certificates, (void **)&byte_buf_ptr, i);

        CERT_BLOB cert_blob;

        cert_blob.pbData = byte_buf_ptr->buffer;
        cert_blob.cbData = (DWORD)byte_buf_ptr->len;

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
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate blob, error code %d.", GetLastError());
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        BOOL add_result = CertAddCertificateContextToStore(*store, cert_context, CERT_STORE_ADD_ALWAYS, NULL);
        if (!add_result) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: unable to add , error code %d.", GetLastError());
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }

        if (i != cert_count - 1 || !add_result) {
            CertFreeCertificateContext(cert_context);
        } else {
            *certs = cert_context;
        }

        if (!add_result) {
            goto clean_up;
        }
    }

    struct aws_byte_buf *private_key_ptr = NULL;
    DWORD decoded_len = 0;
    enum aws_certificate_type cert_type = AWS_CT_X509_UNKNOWN;
    size_t private_key_count = aws_array_list_length(&private_keys);
    for (size_t i = 0; i < private_key_count; ++i) {
        aws_array_list_get_at_ptr(&private_keys, (void **)&private_key_ptr, i);

        if (CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                PKCS_RSA_PRIVATE_KEY,
                private_key_ptr->buffer,
                (DWORD)private_key_ptr->len,
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
                     private_key_ptr->buffer,
                     (DWORD)private_key_ptr->len,
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

    struct aws_uuid uuid;
    if (aws_uuid_init(&uuid)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to create a uuid.");
        goto clean_up;
    }

    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_str, sizeof(uuid_str));
    uuid_buf.len = 0;
    aws_uuid_to_str(&uuid, &uuid_buf);

    switch (cert_type) {
        case AWS_CT_X509_RSA:
            result = s_cert_context_import_rsa_private_key(certs, key, decoded_len, uuid_str);
            break;

#ifndef AWS_SUPPORT_WIN7
        case AWS_CT_X509_ECC:
            result = s_cert_context_import_ecc_private_key(certs, alloc, key, decoded_len, uuid_str);
            break;
#endif /* AWS_SUPPORT_WIN7 */

        default:
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to decode private key");
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
    }

clean_up:
    aws_cert_chain_clean_up(&certificates);
    aws_array_list_clean_up(&certificates);
    aws_cert_chain_clean_up(&private_keys);
    aws_array_list_clean_up(&private_keys);

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
    }

    return result;
}

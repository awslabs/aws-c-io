/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
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
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
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
        return false;
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_PKI, "static: determined registry value for lookup as %d.", (int)store_val);
    location_of_next_segment += 1;
    char *store_path_start = location_of_next_segment;
    location_of_next_segment = strchr(location_of_next_segment, '\\');

    if (!location_of_next_segment) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate path %s.", cert_path);
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    /* The store_val value has to be only the path segment related to the physical store. Looking
       at the docs, 128 bytes should be plenty to store that segment.
       https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/system-store-locations */
    char store_path[128] = {0};
    AWS_ASSERT(location_of_next_segment - store_path_start < sizeof(store_path));
    memcpy(store_path, store_path_start, location_of_next_segment - store_path_start);

    location_of_next_segment += 1;
    if (strlen(location_of_next_segment) != CERT_HASH_STR_LEN) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path %s. %s should have been"
            " 40 bytes of hex encoded data",
            cert_path,
            location_of_next_segment);
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    *cert_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV)NULL, CERT_STORE_OPEN_EXISTING_FLAG | store_val, store_path);

    if (!*cert_store) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate path %s. Failed to load cert store", cert_path);
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
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
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    *certs = CertFindCertificateInStore(
        *cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &cert_hash, NULL);

    if (!*certs) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: invalid certificate path %s. "
            "The referenced certificate was not found in the certificate store.",
            cert_path);
        aws_close_cert_store(*cert_store);
        *cert_store = NULL;
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    return AWS_OP_SUCCESS;
}

int aws_import_trusted_certificates(
    struct aws_allocator *alloc,
    const struct aws_byte_cursor *certificates_blob,
    HCERTSTORE *cert_store) {
    struct aws_array_list certificates;
    *cert_store = NULL;

    if (aws_array_list_init_dynamic(&certificates, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, certificates_blob, &certificates)) {
        aws_array_list_clean_up(&certificates);
        return AWS_OP_ERR;
    }

    int error_code = AWS_OP_SUCCESS;
    size_t cert_count = aws_array_list_length(&certificates);

    HCERTSTORE tmp_cert_store =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);
    *cert_store = tmp_cert_store;
    if (!*cert_store) {
        error_code = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
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
            &cert_context);

        if (!query_res) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate blob.");
            error_code = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        CertAddCertificateContextToStore(*cert_store, cert_context, CERT_STORE_ADD_ALWAYS, NULL);
        CertFreeCertificateContext(cert_context);
    }

clean_up:
    aws_cert_chain_clean_up(&certificates);
    aws_array_list_clean_up(&certificates);

    if (error_code && *cert_store) {
        *cert_store = NULL;
        aws_close_cert_store(*cert_store);
    }
    return error_code;
}

void aws_close_cert_store(HCERTSTORE cert_store) {
    CertCloseStore(cert_store, 0);
}

int aws_import_key_pair_to_cert_context(
    struct aws_allocator *alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    HCERTSTORE *store,
    PCCERT_CONTEXT *certs) {

    struct aws_array_list certificates, private_keys;
    *certs = NULL;
    *store = NULL;
    if (aws_array_list_init_dynamic(&certificates, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, public_cert_chain, &certificates)) {
        aws_array_list_clean_up(&certificates);
        return AWS_OP_ERR;
    }

    if (aws_array_list_init_dynamic(&private_keys, alloc, 1, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, private_key, &private_keys)) {
        aws_array_list_clean_up(&private_keys);
        return AWS_OP_ERR;
    }

    int error_code = AWS_OP_SUCCESS;
    size_t cert_count = aws_array_list_length(&certificates);
    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: loading certificate chain with %d certificates.", (int)cert_count);
    *store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);

    if (!*store) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to load in-memory/ephemeral certificate store.");
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    CERT_CONTEXT *cert_context = NULL;
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
            &cert_context);

        if (!query_res) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: invalid certificate blob.");
            error_code = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        CertAddCertificateContextToStore(*store, cert_context, CERT_STORE_ADD_ALWAYS, NULL);

        if (i != cert_count - 1) {
            CertFreeCertificateContext(cert_context);
        } else {
            *certs = cert_context;
        }
    }

    struct aws_uuid uuid;

    if (aws_uuid_init(&uuid)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to load a uuid. This should never happen.");
        error_code = AWS_OP_ERR;
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

    HCRYPTPROV crypto_prov = 0;
    BOOL success = CryptAcquireContextW(&crypto_prov, uuid_wstr, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);

    if (!success) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: error creating a new crypto context for key %s with errno %d",
            uuid_str,
            (int)GetLastError());
        error_code = AWS_OP_ERR;
        goto clean_up;
    }

    struct aws_byte_buf *private_key_ptr = NULL;
    aws_array_list_get_at_ptr(&private_keys, (void **)&private_key_ptr, 0);
    BYTE *key = NULL;

    DWORD decoded_len = 0;
    success = CryptDecodeObjectEx(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_RSA_PRIVATE_KEY,
        private_key_ptr->buffer,
        (DWORD)private_key_ptr->len,
        CRYPT_DECODE_ALLOC_FLAG,
        0,
        &key,
        &decoded_len);
    HCRYPTKEY h_key = 0;
    success = CryptImportKey(crypto_prov, key, decoded_len, 0, 0, &h_key);
    LocalFree(key);
    CryptDestroyKey(h_key);

    CRYPT_KEY_PROV_INFO key_prov_info;
    AWS_ZERO_STRUCT(key_prov_info);
    key_prov_info.pwszContainerName = uuid_wstr;
    key_prov_info.dwProvType = PROV_RSA_FULL;
    key_prov_info.dwKeySpec = AT_KEYEXCHANGE;

    success = CertSetCertificateContextProperty(*certs, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info);
    CryptReleaseContext(crypto_prov, 0);

    if (!success) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI,
            "static: error creating a new certificate context for key %s with errno %d",
            uuid_str,
            (int)GetLastError());
        error_code = AWS_OP_ERR;
        goto clean_up;
    }

clean_up:
    aws_cert_chain_clean_up(&certificates);
    aws_array_list_clean_up(&certificates);
    aws_cert_chain_clean_up(&private_keys);
    aws_array_list_clean_up(&private_keys);

    if (error_code && *store != NULL) {
        aws_close_cert_store(*store);
        *store = NULL;
    }

    if (error_code && *certs) {
        CertFreeCertificateContext(*certs);
        *certs = NULL;
    }

    return error_code;
}

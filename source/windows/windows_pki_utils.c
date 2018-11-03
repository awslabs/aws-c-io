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

#include <aws/common/clock.h>

#include <Windows.h>

#if _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

#define CERT_HASH_STR_LEN 40
#define CERT_HASH_LEN 20

int aws_load_cert_from_system_cert_store(const char *cert_path, HCERTSTORE *cert_store, PCCERT_CONTEXT *certs) {

    char *location_of_next_segment = strchr(cert_path, '\\');

    if (!location_of_next_segment) {
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

    location_of_next_segment += 1;
    char *store_path_start = location_of_next_segment;
    location_of_next_segment = strchr(location_of_next_segment, '\\');

    if (!location_of_next_segment) {
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    /* The store_val value has to be only the path segment related to the physical store. Looking
       at the docs, 128 bytes should be plenty to store that segment.
       https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/system-store-locations */
    char store_path[128] = {0};
    assert(location_of_next_segment - store_path_start < sizeof(store_path));
    memcpy(store_path, store_path_start, location_of_next_segment - store_path_start);

    location_of_next_segment += 1;
    if (strlen(location_of_next_segment) != CERT_HASH_STR_LEN) {
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    *cert_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV)NULL, CERT_STORE_OPEN_EXISTING_FLAG | store_val, store_path);

    if (!cert_store) {
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
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    *certs = CertFindCertificateInStore(
            *cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, &cert_hash, NULL);

    if (!certs) {
        aws_close_cert_store(*cert_store);
        *cert_store = NULL;
        return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
    }

    return AWS_OP_SUCCESS;
}

int aws_import_trusted_certificates(
        struct aws_allocator *alloc,
        struct aws_byte_buf *certificates_blob,
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
        error_code = aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        goto clean_up;
    }

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
        struct aws_byte_buf *public_cert_chain,
        struct aws_byte_buf *private_key,
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

    *store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);

    if (!*store) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
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

    uint64_t sys_time = 0;
    uint64_t hw_time = 0;
    aws_high_res_clock_get_ticks(&hw_time);
    aws_sys_clock_get_ticks(&sys_time);

    /* TODO: implement a real GUID .... This will do for now.*/
    wchar_t temp_guid[128];
    memset(temp_guid, 0, sizeof(temp_guid));
    swprintf_s(temp_guid, 128, L"%llu_%llu", hw_time, sys_time);
    HCRYPTPROV crypto_prov = 0;
    BOOL success = CryptAcquireContextW(&crypto_prov, temp_guid, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    (void)success;
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
    key_prov_info.pwszContainerName = temp_guid;
    key_prov_info.dwProvType = PROV_RSA_FULL;
    key_prov_info.dwKeySpec = AT_KEYEXCHANGE;

    success = CertSetCertificateContextProperty(*certs, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info);
    CryptReleaseContext(crypto_prov, 0);
    (void)success;

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

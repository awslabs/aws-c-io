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

#include <aws/common/encoding.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int s_translate_and_raise_file_open_error(int error_no) {
    switch (error_no) {
        case EPERM:
        case EACCES:
            return aws_raise_error(AWS_IO_NO_PERMISSION);
        case EISDIR:
        case ENAMETOOLONG:
        case ENOENT:
            return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
        case ENFILE:
            return aws_raise_error(AWS_IO_MAX_FDS_EXCEEDED);
        case ENOMEM:
            return aws_raise_error(AWS_ERROR_OOM);
        default:
            return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }
}

int aws_byte_buf_init_from_file(struct aws_byte_buf *out_buf, struct aws_allocator *alloc, const char *filename) {
/* yeah yeah, I know and I don't care. */
#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about fopen() being insecure */
#endif                              /* _MSC_VER */

    AWS_ZERO_STRUCT(*out_buf);
    FILE *fp = fopen(filename, "rb");

    if (fp) {
        if (fseek(fp, 0L, SEEK_END)) {
            fclose(fp);
            return s_translate_and_raise_file_open_error(errno);
        }

        size_t allocation_size = (size_t)ftell(fp) + 1;
        /* yes I know this breaks the coding conventions rule on init and free being at the same scope,
         * but in this case that doesn't make sense since the user would have to know the length of the file.
         * We'll tell the user that we allocate here and if we succeed they free. */
        if (aws_byte_buf_init(alloc, out_buf, allocation_size)) {
            fclose(fp);
            return AWS_OP_ERR;
        }

        /* while WE ban null terminator APIs, unfortunately much of the world is still stuck in the dark ages of
         * 1970 and we unfortunately have to call into their code on occasion.
         * Go ahead and add one here, but don't make it part of the length. */
        out_buf->len = out_buf->capacity - 1;
        out_buf->buffer[out_buf->len] = 0;

        if (fseek(fp, 0L, SEEK_SET)) {
            aws_byte_buf_clean_up(out_buf);
            fclose(fp);
            return s_translate_and_raise_file_open_error(errno);
        }

        size_t read = fread(out_buf->buffer, 1, out_buf->len, fp);
        fclose(fp);
        if (read < out_buf->len) {
            aws_secure_zero(out_buf->buffer, out_buf->len);
            aws_byte_buf_clean_up(out_buf);
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }

        return AWS_OP_SUCCESS;
    }

    return s_translate_and_raise_file_open_error(errno);
}

enum PEM_PARSE_STATE {
    BEGIN,
    ON_DATA,
};

void aws_cert_chain_clean_up(struct aws_array_list *cert_chain) {
    for (size_t i = 0; i < aws_array_list_length(cert_chain); ++i) {
        struct aws_byte_buf *decoded_buffer_ptr = NULL;
        aws_array_list_get_at_ptr(cert_chain, (void **)&decoded_buffer_ptr, i);

        if (decoded_buffer_ptr) {
            aws_secure_zero(decoded_buffer_ptr->buffer, decoded_buffer_ptr->len);
            aws_byte_buf_clean_up(decoded_buffer_ptr);
        }
    }

    /* remember, we don't own it so we don't free it, just undo whatever mutations we've done at this point. */
    aws_array_list_clear(cert_chain);
}

static int s_convert_pem_to_raw_base64(
    struct aws_allocator *allocator,
    const struct aws_byte_buf *pem,
    struct aws_array_list *cert_chain_or_key) {
    enum PEM_PARSE_STATE state = BEGIN;

    struct aws_byte_buf current_cert;
    struct aws_byte_cursor current_cert_cursor;
    const char *begin_header = "-----BEGIN";
    const char *end_header = "-----END";
    size_t begin_header_len = strlen(begin_header);
    size_t end_header_len = strlen(end_header);
    bool on_length_calc = true;

    struct aws_array_list split_buffers;
    if (aws_array_list_init_dynamic(&split_buffers, allocator, 16, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_split_on_char((struct aws_byte_buf *)pem, '\n', &split_buffers)) {
        aws_array_list_clean_up(&split_buffers);
        return AWS_OP_ERR;
    }

    size_t split_count = aws_array_list_length(&split_buffers);
    size_t i = 0;
    size_t index_of_current_cert_start = 0;
    size_t current_cert_len = 0;

    while (i < split_count) {
        struct aws_byte_cursor *current_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&split_buffers, (void **)&current_buf_ptr, i);

        /* burn off the padding in the buffer first.
         * Worst case we'll only have to do this once per line in the buffer. */
        while (current_buf_ptr->len && isspace(*current_buf_ptr->ptr)) {
            aws_byte_cursor_advance(current_buf_ptr, 1);
        }

        /* handle CRLF on Windows by burning '\r' off the end of the buffer */
        if (current_buf_ptr->len && (current_buf_ptr->ptr[current_buf_ptr->len - 1] == '\r')) {
            current_buf_ptr->len--;
        }

        switch (state) {
            case BEGIN:
                if (current_buf_ptr->len > begin_header_len &&
                    !strncmp((const char *)current_buf_ptr->ptr, begin_header, begin_header_len)) {
                    state = ON_DATA;
                    index_of_current_cert_start = i + 1;
                }
                ++i;
                break;
            /* this loops through the lines containing data twice. First to figure out the length, a second
             * time to actually copy the data. */
            case ON_DATA:
                /* Found end tag. */
                if (current_buf_ptr->len > end_header_len &&
                    !strncmp((const char *)current_buf_ptr->ptr, end_header, end_header_len)) {
                    if (on_length_calc) {
                        on_length_calc = false;
                        state = ON_DATA;
                        i = index_of_current_cert_start;

                        if (aws_byte_buf_init(allocator, &current_cert, current_cert_len)) {
                            goto end_of_loop;
                        }

                        current_cert.len = current_cert.capacity;
                        current_cert_cursor = aws_byte_cursor_from_buf(&current_cert);
                    } else {
                        if (aws_array_list_push_back(cert_chain_or_key, &current_cert)) {
                            aws_secure_zero(&current_cert.buffer, current_cert.len);
                            aws_byte_buf_clean_up(&current_cert);
                            goto end_of_loop;
                        }
                        state = BEGIN;
                        on_length_calc = true;
                        current_cert_len = 0;
                        ++i;
                    }
                    /* actually on a line with data in it. */
                } else {
                    if (!on_length_calc) {
                        aws_byte_cursor_write(&current_cert_cursor, current_buf_ptr->ptr, current_buf_ptr->len);
                    } else {
                        current_cert_len += current_buf_ptr->len;
                    }
                    ++i;
                }
                break;
        }
    }

end_of_loop:
    aws_array_list_clean_up(&split_buffers);

    if (state == BEGIN && aws_array_list_length(cert_chain_or_key) > 0) {
        return AWS_OP_SUCCESS;
    }

    aws_cert_chain_clean_up(cert_chain_or_key);
    return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
}

int aws_decode_pem_to_buffer_list(
    struct aws_allocator *alloc,
    const struct aws_byte_buf *pem_buffer,
    struct aws_array_list *cert_chain_or_key) {
    assert(aws_array_list_length(cert_chain_or_key) == 0);
    struct aws_array_list base_64_buffer_list;

    if (aws_array_list_init_dynamic(&base_64_buffer_list, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    int err_code = AWS_OP_ERR;

    if (s_convert_pem_to_raw_base64(alloc, pem_buffer, &base_64_buffer_list)) {
        goto cleanup_base64_buffer_list;
    }

    for (size_t i = 0; i < aws_array_list_length(&base_64_buffer_list); ++i) {
        size_t decoded_len = 0;
        struct aws_byte_buf *byte_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&base_64_buffer_list, (void **)&byte_buf_ptr, i);

        if (aws_base64_compute_decoded_len((const char *)byte_buf_ptr->buffer, byte_buf_ptr->len, &decoded_len)) {
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto cleanup_output_due_to_error;
        }

        struct aws_byte_buf decoded_buffer;

        if (aws_byte_buf_init(alloc, &decoded_buffer, decoded_len)) {
            goto cleanup_output_due_to_error;
        }

        if (aws_base64_decode(byte_buf_ptr, &decoded_buffer)) {
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            aws_byte_buf_clean_up(&decoded_buffer);
            goto cleanup_output_due_to_error;
        }

        if (aws_array_list_push_back(cert_chain_or_key, &decoded_buffer)) {
            aws_byte_buf_clean_up(&decoded_buffer);
            goto cleanup_output_due_to_error;
        }
    }

    err_code = AWS_OP_SUCCESS;

cleanup_base64_buffer_list:
    aws_cert_chain_clean_up(&base_64_buffer_list);
    aws_array_list_clean_up(&base_64_buffer_list);

    return err_code;

cleanup_output_due_to_error:
    aws_cert_chain_clean_up(&base_64_buffer_list);
    aws_array_list_clean_up(&base_64_buffer_list);

    aws_cert_chain_clean_up(cert_chain_or_key);

    return AWS_OP_ERR;
}

int aws_read_and_decode_pem_file_to_buffer_list(
    struct aws_allocator *alloc,
    const char *filename,
    struct aws_array_list *cert_chain_or_key) {
    struct aws_byte_buf raw_file_buffer;

    if (aws_byte_buf_init_from_file(&raw_file_buffer, alloc, filename)) {
        return AWS_OP_ERR;
    }
    assert(raw_file_buffer.buffer);

    if (aws_decode_pem_to_buffer_list(alloc, &raw_file_buffer, cert_chain_or_key)) {
        aws_secure_zero(raw_file_buffer.buffer, raw_file_buffer.len);
        aws_byte_buf_clean_up(&raw_file_buffer);
        return AWS_OP_ERR;
    }

    aws_secure_zero(raw_file_buffer.buffer, raw_file_buffer.len);
    aws_byte_buf_clean_up(&raw_file_buffer);

    return AWS_OP_SUCCESS;
}

#ifdef __MACH__
#    include <Security/SecCertificate.h>
#    include <Security/SecKey.h>
#    include <Security/Security.h>

int aws_import_public_and_private_keys_to_identity(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    struct aws_byte_buf *public_cert_chain,
    struct aws_byte_buf *private_key,
    CFArrayRef *identity) {

    size_t total_len = public_cert_chain->len + private_key->len;
    struct aws_byte_buf aggregate_buffer;

    if (aws_byte_buf_init(alloc, &aggregate_buffer, total_len)) {
        return AWS_OP_ERR;
    }

    aws_byte_buf_cat(&aggregate_buffer, 2, public_cert_chain, private_key);
    CFDataRef aggregate_certificate_data = CFDataCreate(cf_alloc, aggregate_buffer.buffer, aggregate_buffer.len);

    if (!aggregate_certificate_data) {
        aws_byte_buf_clean_up(&aggregate_buffer);
        return AWS_OP_ERR;
    }

    CFArrayRef import_output;
    SecExternalFormat format = kSecFormatUnknown;
    SecExternalItemType item_type = kSecItemTypeAggregate;

    SecItemImportExportKeyParameters import_params;
    AWS_ZERO_STRUCT(import_params);
    import_params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    import_params.passphrase = CFSTR("");

    SecKeychainRef import_keychain = NULL;
    SecKeychainCopyDefault(&import_keychain);

    OSStatus status = SecItemImport(
        aggregate_certificate_data, NULL, &format, &item_type, 0, &import_params, import_keychain, &import_output);

    CFRelease(aggregate_certificate_data);
    aws_byte_buf_clean_up(&aggregate_buffer);

    if (status != errSecSuccess && status != errSecDuplicateItem) {
        return AWS_OP_ERR;
    }

    SecCertificateRef certificate_ref = NULL;

    /* if it's already there, just conver this over to a cert and then let the keychain give it back to us. */
    if (status == errSecDuplicateItem) {
        struct aws_array_list cert_chain_list;

        if (aws_array_list_init_dynamic(&cert_chain_list, alloc, 2, sizeof(struct aws_byte_buf))) {
            return AWS_OP_ERR;
        }

        if (aws_decode_pem_to_buffer_list(alloc, public_cert_chain, &cert_chain_list)) {
            aws_array_list_clean_up(&cert_chain_list);
            return AWS_OP_ERR;
        }

        struct aws_byte_buf *root_cert_ptr = NULL;
        aws_array_list_get_at_ptr(&cert_chain_list, (void **)&root_cert_ptr, 0);
        CFDataRef root_cert_data = CFDataCreate(cf_alloc, root_cert_ptr->buffer, root_cert_ptr->len);

        if (root_cert_data) {
            certificate_ref = SecCertificateCreateWithData(cf_alloc, root_cert_data);
            CFRelease(root_cert_data);
        }

        aws_array_list_clean_up(&cert_chain_list);
    } else {
        certificate_ref = (SecCertificateRef)CFArrayGetValueAtIndex(import_output, 0);
    }

    if (certificate_ref) {
        SecIdentityRef identity_output;
        status = SecIdentityCreateWithCertificate(import_keychain, certificate_ref, &identity_output);

        CFRelease(import_keychain);
        if (import_output) {
            CFRelease(import_output);
        }

        if (status == errSecSuccess) {
            CFTypeRef certs[] = {identity_output};
            *identity = CFArrayCreate(cf_alloc, (const void **)certs, 1L, &kCFTypeArrayCallBacks);
            return AWS_OP_SUCCESS;
        }
    }

    return AWS_OP_ERR;
}

int aws_import_pkcs12_to_identity(
    CFAllocatorRef cf_alloc,
    struct aws_byte_buf *pkcs12_buffer,
    struct aws_byte_buf *password,
    CFArrayRef *identity) {
    CFDataRef pkcs12_data = CFDataCreate(cf_alloc, pkcs12_buffer->buffer, pkcs12_buffer->len);
    CFArrayRef items = NULL;

    CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(cf_alloc, 0, NULL, NULL);

    CFStringRef password_ref = CFSTR("");

    if (password->len) {
        password_ref = CFStringCreateWithBytes(cf_alloc, password->buffer, password->len, kCFStringEncodingUTF8, false);
    }

    CFDictionaryAddValue(dictionary, kSecImportExportPassphrase, password_ref);

    OSStatus status = SecPKCS12Import(pkcs12_data, dictionary, &items);
    CFRelease(pkcs12_data);

    if (password_ref) {
        CFRelease(password_ref);
    }

    CFRelease(dictionary);

    if (status == errSecSuccess) {
        CFTypeRef item = (CFTypeRef)CFArrayGetValueAtIndex(items, 0);

        CFTypeRef identity_ref = (CFTypeRef)CFDictionaryGetValue((CFDictionaryRef)item, kSecImportItemIdentity);
        if (identity_ref) {
            CFRetain(identity_ref);
            CFTypeRef certs[] = {identity_ref};
            *identity = CFArrayCreate(cf_alloc, (const void **)certs, 1L, &kCFTypeArrayCallBacks);
        }

        CFRelease(items);
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_import_trusted_certificates(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    struct aws_byte_buf *certificates_blob,
    CFArrayRef *certs) {
    struct aws_array_list certificates;

    if (aws_array_list_init_dynamic(&certificates, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, certificates_blob, &certificates)) {
        aws_array_list_clean_up(&certificates);
        return AWS_OP_ERR;
    }

    size_t cert_count = aws_array_list_length(&certificates);
    CFMutableArrayRef temp_cert_array = CFArrayCreateMutable(cf_alloc, cert_count, &kCFTypeArrayCallBacks);

    int err = AWS_OP_SUCCESS;

    for (size_t i = 0; i < cert_count; ++i) {
        struct aws_byte_buf *byte_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&certificates, (void **)&byte_buf_ptr, i);

        CFDataRef cert_blob = CFDataCreate(cf_alloc, byte_buf_ptr->buffer, byte_buf_ptr->len);

        if (cert_blob) {
            SecCertificateRef certificate_ref = SecCertificateCreateWithData(cf_alloc, cert_blob);
            CFArrayAppendValue(temp_cert_array, certificate_ref);
            CFRelease(cert_blob);
        } else {
            err = AWS_OP_SUCCESS;
        }
    }

    *certs = temp_cert_array;
    aws_cert_chain_clean_up(&certificates);
    aws_array_list_clean_up(&certificates);
    return err;
}

void aws_release_identity(CFArrayRef identity) {
    CFRelease(identity);
}

void aws_release_certificates(CFArrayRef certs) {
    CFRelease(certs);
}

#endif

#ifdef _WIN32

#include <aws/common/clock.h>

int aws_import_trusted_certificates(struct aws_allocator *alloc, struct aws_byte_buf *certificates_blob, HCERTSTORE *cert_store) {
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

    HCERTSTORE tmp_cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);
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
        BOOL query_res = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &cert_blob,
            CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0, NULL, &content_type, NULL, NULL, NULL, &cert_context);

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

int aws_import_installed_cert_to_cert_context(HCERTSTORE cert_store, struct aws_allocator *alloc,
    const char *path, PCCERT_CONTEXT *certs) {
    (void)cert_store;
    (void)alloc;
    (void)path;
    (void)certs;

    return AWS_OP_SUCCESS;
}

int aws_import_key_pair_to_cert_context(struct aws_allocator *alloc,
    struct aws_byte_buf *public_cert_chain, struct aws_byte_buf *private_key, HCERTSTORE *store, PCCERT_CONTEXT *certs) {

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
        BOOL query_res = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &cert_blob,
            CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0, NULL, &content_type, 
            NULL, NULL, NULL, &cert_context);

        if (!query_res) {
            error_code = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }
        
        CertAddCertificateContextToStore(*store, cert_context, CERT_STORE_ADD_ALWAYS, NULL);

        if (i != cert_count - 1) {
            CertFreeCertificateContext(cert_context);
        }
        else {
            *certs = cert_context;
        }
    }

    uint64_t sys_time = 0;
    uint64_t hw_time = 0;
    aws_high_res_clock_get_ticks(&hw_time);
    aws_sys_clock_get_ticks(&sys_time);

    wchar_t temp_guid[128];
    memset(temp_guid, 0, sizeof(temp_guid));
    swprintf_s(temp_guid, 128, L"%llu_%llu", hw_time, sys_time);
    HCRYPTPROV crypto_prov = 0;
    BOOL success = CryptAcquireContextW(&crypto_prov, temp_guid, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
    (void)success;
    struct aws_byte_buf* private_key_ptr = NULL;
    aws_array_list_get_at_ptr(&private_keys, (void **)&private_key_ptr, 0);
    BYTE *key = NULL;

    //PCRYPT_PRIVATE_KEY_INFO key_info = 0;
    DWORD decoded_len = 0;
    success = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, 
        private_key_ptr->buffer, (DWORD)private_key_ptr->len, CRYPT_DECODE_ALLOC_FLAG, 0, &key, &decoded_len);
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

int aws_import_pkcs12_to_cert_context(struct aws_allocator *alloc,
    struct aws_byte_buf *pkcs12_buffer, PCCERT_CONTEXT *certs) {
    (void)alloc;
    (void)pkcs12_buffer;
    (void)certs;
    HCERTSTORE cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, (ULONG_PTR)NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);

    if (!cert_store) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

#endif*/ /* _WIN32 */


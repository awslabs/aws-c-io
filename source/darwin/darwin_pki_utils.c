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

#include <Security/SecCertificate.h>
#include <Security/SecKey.h>
#include <Security/Security.h>

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
    aws_secure_zero(aggregate_buffer.buffer, aggregate_buffer.len);
    aws_byte_buf_clean_up(&aggregate_buffer);

    if (status != errSecSuccess && status != errSecDuplicateItem) {
        return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
    }

    SecCertificateRef certificate_ref = NULL;

    /* if it's already there, just convert this over to a cert and then let the keychain give it back to us. */
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
        assert(root_cert_ptr);
        CFDataRef root_cert_data = CFDataCreate(cf_alloc, root_cert_ptr->buffer, root_cert_ptr->len);

        if (root_cert_data) {
            certificate_ref = SecCertificateCreateWithData(cf_alloc, root_cert_data);
            CFRelease(root_cert_data);
        }

        aws_cert_chain_clean_up(&cert_chain_list);
        aws_array_list_clean_up(&cert_chain_list);
    } else {
        certificate_ref = (SecCertificateRef)CFArrayGetValueAtIndex(import_output, 0);
        /* SecCertificateCreateWithData returns an object with +1 retain, so we need to match that behavior here */
        CFRetain(certificate_ref);
    }

    if (certificate_ref) {
        SecIdentityRef identity_output;
        bool cleanup_import_output = status != errSecDuplicateItem;
        status = SecIdentityCreateWithCertificate(import_keychain, certificate_ref, &identity_output);

        CFRelease(certificate_ref);
        CFRelease(import_keychain);
        if (import_output && cleanup_import_output) {
            CFRelease(import_output);
        }

        if (status == errSecSuccess) {
            CFTypeRef certs[] = {identity_output};
            *identity = CFArrayCreate(cf_alloc, (const void **)certs, 1L, &kCFTypeArrayCallBacks);
            return AWS_OP_SUCCESS;
        }
    } else {
        CFRelease(import_keychain);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
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
            *identity = CFArrayCreate(cf_alloc, &identity_ref, 1L, &kCFTypeArrayCallBacks);
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
            CFRelease(certificate_ref);
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

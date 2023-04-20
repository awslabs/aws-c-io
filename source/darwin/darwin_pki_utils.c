/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/private/pki_utils.h>

#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>

#include <Security/SecCertificate.h>
#include <Security/SecKey.h>
#include <Security/Security.h>

/* SecureTransport is not thread-safe during identity import */
/* https://developer.apple.com/documentation/security/certificate_key_and_trust_services/working_with_concurrency */
static struct aws_mutex s_sec_mutex = AWS_MUTEX_INIT;

#if !defined(AWS_OS_IOS)

/*
 * Helper function to import ECC private key in PEM format into `import_keychain`. Return
 * AWS_OP_SUCCESS if successfully imported a private key or find a duplicate key in the
 * `import_keychain`, otherwise return AWS_OP_ERR.
 * `private_key`: UTF-8 key data in PEM format. If the key file contains multiple key sections,
 * the function will only import the first valid key.
 * `import_keychain`: The keychain to be imported to. `import_keychain` should not be NULL.
 */
int aws_import_ecc_key_into_keychain(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *private_key,
    SecKeychainRef import_keychain) {
    // Ensure imported_keychain is not NULL
    AWS_PRECONDITION(import_keychain != NULL);

    int result = AWS_OP_ERR;
    struct aws_array_list decoded_key_buffer_list;
    /* Init empty array list, ideally, the PEM should only has one key included. */
    if (aws_array_list_init_dynamic(&decoded_key_buffer_list, alloc, 1, sizeof(struct aws_byte_buf))) {
        return result;
    }

    /* Decode PEM format file to DER format */
    if (aws_decode_pem_to_buffer_list(alloc, private_key, &decoded_key_buffer_list)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM private key to DER format.");
        goto ecc_import_cleanup;
    }
    AWS_ASSERT(aws_array_list_is_valid(&decoded_key_buffer_list));

    // A PEM file could contains multiple PEM data section. Try importing each PEM section until find the first
    // succeed key.
    for (size_t index = 0; index < aws_array_list_length(&decoded_key_buffer_list); index++) {
        struct aws_byte_buf *decoded_key_buffer = NULL;
        /* We only check the first pem section. Currently, we dont support key with multiple pem section. */
        aws_array_list_get_at_ptr(&decoded_key_buffer_list, (void **)&decoded_key_buffer, index);
        AWS_ASSERT(decoded_key_buffer);
        CFDataRef key_data = CFDataCreate(cf_alloc, decoded_key_buffer->buffer, decoded_key_buffer->len);
        if (!key_data) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error in creating ECC key data system call.");
            continue;
        }

        /* Import ECC key data into keychain. */
        SecExternalFormat format = kSecFormatOpenSSL;
        SecExternalItemType item_type = kSecItemTypePrivateKey;
        SecItemImportExportKeyParameters import_params;
        AWS_ZERO_STRUCT(import_params);
        import_params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        import_params.passphrase = CFSTR("");

        OSStatus key_status =
            SecItemImport(key_data, NULL, &format, &item_type, 0, &import_params, import_keychain, NULL);

        /* Clean up key buffer */
        CFRelease(key_data);

        // As long as we found an imported key, ignore the rest of keys
        if (key_status == errSecSuccess || key_status == errSecDuplicateItem) {
            result = AWS_OP_SUCCESS;
            break;
        } else {
            // Log the error code for key importing
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error importing ECC private key with OSStatus %d", (int)key_status);
        }
    }

ecc_import_cleanup:
    // Zero out the array list and release it
    aws_cert_chain_clean_up(&decoded_key_buffer_list);
    aws_array_list_clean_up(&decoded_key_buffer_list);
    return result;
}

int aws_import_public_and_private_keys_to_identity(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    CFArrayRef *identity,
    const struct aws_string *keychain_path) {

    int result = AWS_OP_ERR;

    CFDataRef cert_data = CFDataCreate(cf_alloc, public_cert_chain->ptr, public_cert_chain->len);
    CFDataRef key_data = CFDataCreate(cf_alloc, private_key->ptr, private_key->len);

    if (!cert_data || !key_data) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    CFArrayRef cert_import_output = NULL;
    CFArrayRef key_import_output = NULL;
    SecExternalFormat format = kSecFormatUnknown;
    SecExternalItemType item_type = kSecItemTypeCertificate;

    SecItemImportExportKeyParameters import_params;
    AWS_ZERO_STRUCT(import_params);
    import_params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    import_params.passphrase = CFSTR("");

    SecCertificateRef certificate_ref = NULL;
    SecKeychainRef import_keychain = NULL;

#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wdeprecated-declarations"
    /* SecKeychain functions are marked as deprecated.
     * Disable compiler warnings for now, but consider removing support for keychain altogether */

    if (keychain_path) {
        OSStatus keychain_status = SecKeychainOpen(aws_string_c_str(keychain_path), &import_keychain);
        if (keychain_status != errSecSuccess) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI,
                "static: error opening keychain \"%s\" with OSStatus %d",
                aws_string_c_str(keychain_path),
                keychain_status);
            return AWS_OP_ERR;
        }
        keychain_status = SecKeychainUnlock(import_keychain, 0, "", true);
        if (keychain_status != errSecSuccess) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI,
                "static: error unlocking keychain \"%s\" with OSStatus %d",
                aws_string_c_str(keychain_path),
                keychain_status);
            return AWS_OP_ERR;
        }
    } else {
        OSStatus keychain_status = SecKeychainCopyDefault(&import_keychain);
        if (keychain_status != errSecSuccess) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: error opening the default keychain with OSStatus %d", keychain_status);
            return AWS_OP_ERR;
        }
    }

#    pragma clang diagnostic pop

    aws_mutex_lock(&s_sec_mutex);

    /* import certificate */
    OSStatus cert_status =
        SecItemImport(cert_data, NULL, &format, &item_type, 0, &import_params, import_keychain, &cert_import_output);

    /* import private key */
    item_type = kSecItemTypePrivateKey;
    OSStatus key_status =
        SecItemImport(key_data, NULL, &format, &item_type, 0, &import_params, import_keychain, &key_import_output);

    CFRelease(cert_data);
    CFRelease(key_data);

    if (cert_status != errSecSuccess && cert_status != errSecDuplicateItem) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error importing certificate with OSStatus %d", (int)cert_status);
        result = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        goto done;
    }

    /*
     * If the key format is unknown, we tried to decode the key into DER format import it.
     * The PEM file might contians multiple key sections, we will only add the first succeed key into the keychain.
     */
    if (key_status == errSecUnknownFormat) {
        AWS_LOGF_TRACE(AWS_LS_IO_PKI, "static: error reading private key format, try ECC key format.");
        if (aws_import_ecc_key_into_keychain(alloc, cf_alloc, private_key, import_keychain)) {
            result = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto done;
        }
    } else if (key_status != errSecSuccess && key_status != errSecDuplicateItem) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error importing private key with OSStatus %d", (int)key_status);
        result = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        goto done;
    }

    /* if it's already there, just convert this over to a cert and then let the keychain give it back to us. */
    if (cert_status == errSecDuplicateItem) {
        /* The text for this log is also in the README for each CRT and v2 IoT SDK.  If changed, please also change
         * where it is referenced. */
        AWS_LOGF_INFO(
            AWS_LS_IO_PKI,
            "static: certificate has an existing certificate-key pair that was previously imported into the Keychain.  "
            "Using key from Keychain instead of the one provided.");
        struct aws_array_list cert_chain_list;

        if (aws_array_list_init_dynamic(&cert_chain_list, alloc, 2, sizeof(struct aws_byte_buf))) {
            result = AWS_OP_ERR;
            goto done;
        }

        if (aws_decode_pem_to_buffer_list(alloc, public_cert_chain, &cert_chain_list)) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: decoding certificate PEM failed.");
            aws_array_list_clean_up(&cert_chain_list);
            result = AWS_OP_ERR;
            goto done;
        }

        struct aws_byte_buf *root_cert_ptr = NULL;
        aws_array_list_get_at_ptr(&cert_chain_list, (void **)&root_cert_ptr, 0);
        AWS_ASSERT(root_cert_ptr);
        CFDataRef root_cert_data = CFDataCreate(cf_alloc, root_cert_ptr->buffer, root_cert_ptr->len);

        if (root_cert_data) {
            certificate_ref = SecCertificateCreateWithData(cf_alloc, root_cert_data);
            CFRelease(root_cert_data);
        }

        aws_cert_chain_clean_up(&cert_chain_list);
        aws_array_list_clean_up(&cert_chain_list);
    } else {
        certificate_ref = (SecCertificateRef)CFArrayGetValueAtIndex(cert_import_output, 0);
        /* SecCertificateCreateWithData returns an object with +1 retain, so we need to match that behavior here */
        CFRetain(certificate_ref);
    }

    /* if we got a cert one way or the other, create the identity and return it */
    if (certificate_ref) {
        SecIdentityRef identity_output;
        OSStatus status = SecIdentityCreateWithCertificate(import_keychain, certificate_ref, &identity_output);
        if (status == errSecSuccess) {
            CFTypeRef certs[] = {identity_output};
            *identity = CFArrayCreate(cf_alloc, (const void **)certs, 1L, &kCFTypeArrayCallBacks);
            result = AWS_OP_SUCCESS;
            goto done;
        }
    }

done:
    aws_mutex_unlock(&s_sec_mutex);
    if (certificate_ref) {
        CFRelease(certificate_ref);
    }
    if (cert_import_output) {
        CFRelease(cert_import_output);
    }
    if (key_import_output) {
        CFRelease(key_import_output);
    }
    if (import_keychain) {
        CFRelease(import_keychain);
    }

    return result;
}

#endif /* !AWS_OS_IOS */

int aws_import_pkcs12_to_identity(
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *pkcs12_cursor,
    const struct aws_byte_cursor *password,
    CFArrayRef *identity) {
    CFDataRef pkcs12_data = CFDataCreate(cf_alloc, pkcs12_cursor->ptr, pkcs12_cursor->len);
    CFArrayRef items = NULL;

    CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(cf_alloc, 0, NULL, NULL);

    CFStringRef password_ref = CFSTR("");

    if (password->len) {
        password_ref = CFStringCreateWithBytes(cf_alloc, password->ptr, password->len, kCFStringEncodingUTF8, false);
    }

    CFDictionaryAddValue(dictionary, kSecImportExportPassphrase, password_ref);

    aws_mutex_lock(&s_sec_mutex);
    OSStatus status = SecPKCS12Import(pkcs12_data, dictionary, &items);
    aws_mutex_unlock(&s_sec_mutex);
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

    AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error importing pkcs#12 certificate OSStatus %d", (int)status);

    return AWS_OP_ERR;
}

int aws_import_trusted_certificates(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *certificates_blob,
    CFArrayRef *certs) {
    struct aws_array_list certificates;

    if (aws_array_list_init_dynamic(&certificates, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, certificates_blob, &certificates)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: decoding CA PEM failed.");
        aws_array_list_clean_up(&certificates);
        return AWS_OP_ERR;
    }

    size_t cert_count = aws_array_list_length(&certificates);
    CFMutableArrayRef temp_cert_array = CFArrayCreateMutable(cf_alloc, cert_count, &kCFTypeArrayCallBacks);

    int err = AWS_OP_SUCCESS;
    aws_mutex_lock(&s_sec_mutex);
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
    aws_mutex_unlock(&s_sec_mutex);

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

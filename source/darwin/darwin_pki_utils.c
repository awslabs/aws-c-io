/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/private/pki_utils.h>

#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/logging.h>
#include <aws/io/pem.h>
#include <aws/io/tls_channel_handler.h>

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
    AWS_PRECONDITION(private_key != NULL);

    int result = AWS_OP_ERR;
    struct aws_array_list decoded_key_buffer_list;

    /* Decode PEM format file to DER format */
    if (aws_pem_objects_init_from_file_contents(&decoded_key_buffer_list, alloc, *private_key)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM private key to DER format.");
        goto ecc_import_cleanup;
    }
    AWS_ASSERT(aws_array_list_is_valid(&decoded_key_buffer_list));

    // A PEM file could contains multiple PEM data section. Try importing each PEM section until find the first
    // succeed key.
    for (size_t index = 0; index < aws_array_list_length(&decoded_key_buffer_list); index++) {
        struct aws_pem_object *pem_object_ptr = NULL;
        /* We only check the first pem section. Currently, we dont support key with multiple pem section. */
        aws_array_list_get_at_ptr(&decoded_key_buffer_list, (void **)&pem_object_ptr, index);
        AWS_ASSERT(pem_object_ptr);
        CFDataRef key_data = CFDataCreate(cf_alloc, pem_object_ptr->data.buffer, pem_object_ptr->data.len);
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
    aws_pem_objects_clean_up(&decoded_key_buffer_list);
    return result;
}

int aws_import_public_and_private_keys_to_identity(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    CFArrayRef *identity,
    const struct aws_string *keychain_path) {
    AWS_PRECONDITION(public_cert_chain != NULL);
    AWS_PRECONDITION(private_key != NULL);

    int result = AWS_OP_ERR;

    CFDataRef cert_data = NULL;
    CFDataRef key_data = NULL;

    CFArrayRef cert_import_output = NULL;
    CFArrayRef key_import_output = NULL;
    SecExternalFormat format = kSecFormatUnknown;
    SecExternalItemType item_type = kSecItemTypeCertificate;

    SecItemImportExportKeyParameters import_params;
    AWS_ZERO_STRUCT(import_params);
    import_params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    import_params.passphrase = CFSTR("");

    struct aws_array_list cert_chain_list;
    AWS_ZERO_STRUCT(cert_chain_list);
    CFDataRef root_cert_data = NULL;
    SecCertificateRef certificate_ref = NULL;
    SecKeychainRef import_keychain = NULL;

    cert_data = CFDataCreate(cf_alloc, public_cert_chain->ptr, public_cert_chain->len);
    if (!cert_data) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed creating public cert chain data.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    key_data = CFDataCreate(cf_alloc, private_key->ptr, private_key->len);
    if (!key_data) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed creating private key data.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

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
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
        keychain_status = SecKeychainUnlock(import_keychain, 0, "", true);
        if (keychain_status != errSecSuccess) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI,
                "static: error unlocking keychain \"%s\" with OSStatus %d",
                aws_string_c_str(keychain_path),
                keychain_status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    } else {
        OSStatus keychain_status = SecKeychainCopyDefault(&import_keychain);
        if (keychain_status != errSecSuccess) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: error opening the default keychain with OSStatus %d", keychain_status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    }

#    pragma clang diagnostic pop

    aws_mutex_lock(&s_sec_mutex);

    /* import certificate */
    OSStatus cert_status =
        SecItemImport(cert_data, NULL, &format, &item_type, 0, &import_params, import_keychain, &cert_import_output);

    /* import private key */
    format = kSecFormatUnknown;
    item_type = kSecItemTypePrivateKey;
    OSStatus key_status =
        SecItemImport(key_data, NULL, &format, &item_type, 0, &import_params, import_keychain, &key_import_output);

    if (cert_status != errSecSuccess && cert_status != errSecDuplicateItem) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error importing certificate with OSStatus %d", (int)cert_status);
        result = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        goto done;
    }

    /*
     * If the key format is unknown, we tried to decode the key into DER format import it.
     * The PEM file might contains multiple key sections, we will only add the first succeed key into the keychain.
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
        if (aws_pem_objects_init_from_file_contents(&cert_chain_list, alloc, *public_cert_chain)) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: decoding certificate PEM failed.");
            result = AWS_OP_ERR;
            goto done;
        }

        struct aws_pem_object *root_cert_ptr = NULL;
        aws_array_list_get_at_ptr(&cert_chain_list, (void **)&root_cert_ptr, 0);
        AWS_ASSERT(root_cert_ptr);
        root_cert_data = CFDataCreate(cf_alloc, root_cert_ptr->data.buffer, root_cert_ptr->data.len);
        if (!root_cert_data) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed creating root cert data.");
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        certificate_ref = SecCertificateCreateWithData(cf_alloc, root_cert_data);
        if (!certificate_ref) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: failed to create certificate.");
            result = aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto done;
        }
    } else {
        certificate_ref = (SecCertificateRef)CFArrayGetValueAtIndex(cert_import_output, 0);
        /* SecCertificateCreateWithData returns an object with +1 retain, so we need to match that behavior here */
        CFRetain(certificate_ref);
    }

    /* we got a cert one way or the other, create the identity and return it */
    AWS_ASSERT(certificate_ref);
    SecIdentityRef identity_output;
    OSStatus status = SecIdentityCreateWithCertificate(import_keychain, certificate_ref, &identity_output);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: error creating identity with OSStatus %d", key_status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    CFTypeRef certs[] = {identity_output};
    *identity = CFArrayCreate(cf_alloc, (const void **)certs, 1L, &kCFTypeArrayCallBacks);
    result = AWS_OP_SUCCESS;

done:
    aws_mutex_unlock(&s_sec_mutex);
    if (certificate_ref) {
        CFRelease(certificate_ref);
    }
    if (root_cert_data) {
        CFRelease(root_cert_data);
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
    if (cert_data) {
        CFRelease(cert_data);
    }
    if (key_data) {
        CFRelease(key_data);
    }
    aws_pem_objects_clean_up(&cert_chain_list);

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

/*
 * Apple's Network framework and SecItem API use of the data protection keychain is currently only implemented
 * on iOS and tvOS. We may add support for MacOS at a later date.
 *
 * MacOS migration from currently deprecated Secure Transport API and file based keychain to
 * Network framework will require it we also migrate from BSD Sockets to Apple's Network Framework.
 *
 * From a breaking existing users perspective, we must also find a way to continue support for the
 * keychain_path field which is currently only bound out to aws-crt-cpp.
 */

int aws_secitem_add_certificate_to_keychain(
    CFAllocatorRef cf_alloc,
    SecCertificateRef cert_ref,
    CFDataRef serial_data,
    CFStringRef label) {

    int result = AWS_OP_ERR;
    OSStatus status;

    CFMutableDictionaryRef add_attributes = NULL;
    CFMutableDictionaryRef delete_query = NULL;

    add_attributes =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(add_attributes, kSecClass, kSecClassCertificate);
    CFDictionaryAddValue(add_attributes, kSecAttrSerialNumber, serial_data);
    CFDictionaryAddValue(add_attributes, kSecAttrLabel, label);
    CFDictionaryAddValue(add_attributes, kSecValueRef, cert_ref);
    status = SecItemAdd(add_attributes, NULL);

    // A duplicate item is handled. All other errors are unhandled.
    if (status != errSecSuccess && status != errSecDuplicateItem) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd certificate failed with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /* A duplicate item error indicates the certificate already exists in the keychain. We delete the
     * existing certificate and re-add the certificate in case there are differences that need to be applied.
     *
     * query should be made up of primary keys only. Optional/non-unique attributes in the query
     * can result in not finding the matching certificate and cause the update operation to fail.
     *
     * Certificate item primary keys we use for the query:
     * kSecAttrSerialNumber: (CFStringRef) value indicates the item's serial number
     *      - We explicity set this value, extracted from the certificate itself as our primary method of determining
     * uniqueness of the certificate.
     *
     * Certificate primary keys we do not use for the query:
     * These can be added in the future if we require a more specified search query.
     * kSecAttrCertificateType: (CFNumberRef) value indicates the item's certificate type
     *      - values see the CSSM_CERT_TYPE enumeration in cssmtype.h
     * https://opensource.apple.com/source/Security/Security-55471/libsecurity_cssm/lib/cssmtype.h.auto.html
     *      - default will try to add common value such as X.509. We do not pass this attribute and allow default value
     * to be used. If we decide to support other types of certificates, we should set and use this value explicitly.
     * kSecAttrIssuer: (CFStringRef) value indicates the item's issuer
     *      - default will try to extract issuer from the certificate itself.
     *        We will not set this attribute and allow default value to be used.
     */
    if (status == errSecDuplicateItem) {
        AWS_LOGF_INFO(
            AWS_LS_IO_PKI,
            "static: Keychain contains existing certificate that was previously imported into the Keychain.  "
            "Deleting existing certificate in keychain.");

        delete_query =
            CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(delete_query, kSecClass, kSecClassCertificate);
        CFDictionaryAddValue(delete_query, kSecAttrSerialNumber, serial_data);

        // delete the existing certificate from keychain
        status = SecItemDelete(delete_query);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemDelete certificate failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        // now try adding it again
        status = SecItemAdd(add_attributes, NULL);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd certificate failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    }

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully imported certificate into SecItem keychain.");

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    if (add_attributes)
        CFRelease(add_attributes);
    if (delete_query)
        CFRelease(delete_query);

    return result;
}

int aws_secitem_add_private_key_to_keychain(
    CFAllocatorRef cf_alloc,
    SecKeyRef key_ref,
    CFStringRef label,
    CFDataRef application_label) {

    int result = AWS_OP_ERR;
    OSStatus status;

    CFMutableDictionaryRef add_attributes = NULL;
    CFMutableDictionaryRef delete_query = NULL;

    add_attributes =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(add_attributes, kSecClass, kSecClassKey);
    CFDictionaryAddValue(add_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(add_attributes, kSecAttrApplicationLabel, application_label);
    CFDictionaryAddValue(add_attributes, kSecAttrLabel, label);
    CFDictionaryAddValue(add_attributes, kSecValueRef, key_ref);
    status = SecItemAdd(add_attributes, NULL);

    // A duplicate item is handled. All other errors are unhandled.
    if (status != errSecSuccess && status != errSecDuplicateItem) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd private key failed with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /* A duplicate item error indicates the private key already exists in the keychain. We delete the
     * existing private key and re-add the private-key in case there are differences that need to be applied.
     *
     * query should be made up of primary keys only. Optional/non-unique attributes in the query
     * can result in not finding the matching private key and cause the update operation to fail.
     *
     * Private Key item primary keys we use for the query:
     * kSecAttrKeyClass: (CFTypeRef) value indicates item's cryptographic key class
     *      - We explicitly set this value to kSecAttrKeyClassPrivate
     * kSecAttrApplicationLabel: (CFStringRef) value indicates item's application label.
     *      - We pull this value out of the SecKeyRef. It's the hash of the public key stored within.
     *
     * Private Key primary keys we do not use for the query:
     * These can be added in the future if we require a more specified search query.
     * kSecAttrApplicationTag: (CFDataRef) value indicates the item's private tag.
     * kSecAttrKeySizeInBits: (CFNumberRef) value indicates the number of bits in a cryptographic key.
     * kSecAttrEffectiveKeySize: (CFNumberRef) value indicates the effective number of bits in a crytographic key.
     */

    if (status == errSecDuplicateItem) {
        AWS_LOGF_INFO(
            AWS_LS_IO_PKI,
            "static: Keychain contains existing private key that was previously imported into the Keychain.  "
            "Deleting private key in keychain.");

        delete_query =
            CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(delete_query, kSecClass, kSecClassKey);
        CFDictionaryAddValue(delete_query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
        CFDictionaryAddValue(delete_query, kSecAttrApplicationLabel, application_label);

        // delete the existing private key from keychain
        status = SecItemDelete(delete_query);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemDelete private key failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        // now try adding it again
        status = SecItemAdd(add_attributes, NULL);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd private key failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    }

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully imported private key into SecItem keychain.");

    result = AWS_OP_SUCCESS;
done:
    // cleanup
    if (add_attributes)
        CFRelease(add_attributes);
    if (delete_query)
        CFRelease(delete_query);

    return result;
}

int aws_secitem_get_identity(CFAllocatorRef cf_alloc, CFDataRef serial_data, sec_identity_t *out_identity) {

    int result = AWS_OP_ERR;
    OSStatus status;
    CFMutableDictionaryRef search_query = NULL;
    SecIdentityRef sec_identity_ref = NULL;

    /*
     * SecItem identity is created when a certificate matches a private key in the keychain.
     * Since a private key may be associated with multiple certificates, searching for the
     * identity using a unique attribute of the certificate is required. This is why we use
     * the serial_data from the certificate as the search parameter.
     */
    search_query =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(search_query, kSecClass, kSecClassIdentity);
    CFDictionaryAddValue(search_query, kSecAttrSerialNumber, serial_data);
    CFDictionaryAddValue(search_query, kSecReturnRef, kCFBooleanTrue);

    /*
     * Copied or created CF items must have CFRelease called on them or you leak memory. This identity needs to
     * have CFRelease called on it at some point or it will leak.
     */
    status = SecItemCopyMatching(search_query, (CFTypeRef *)&sec_identity_ref);

    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching identity failed with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    *out_identity = sec_identity_create(sec_identity_ref);

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully retrieved identity from keychain.");

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    if (search_query)
        CFRelease(search_query);
    if (sec_identity_ref)
        CFRelease(sec_identity_ref);

    return result;
}

int aws_secitem_import_cert_and_key(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    sec_identity_t *secitem_identity,
    const struct aws_secitem_options *secitem_options) {

// We currently only support Apple's network framework and SecItem keychain API on iOS.
#if !defined(AWS_USE_SECITEM)
    AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Secitem not supported on this platform.");
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif /* !AWS_USE_SECITEM */

    AWS_PRECONDITION(public_cert_chain != NULL);
    AWS_PRECONDITION(private_key != NULL);

    int result = AWS_OP_ERR;

    CFErrorRef error = NULL;

    CFDataRef cert_data = NULL;
    SecCertificateRef cert_ref = NULL;
    CFDataRef cert_serial_data = NULL;
    CFStringRef cert_label_ref = NULL;

    CFMutableDictionaryRef key_attributes = NULL;
    CFDictionaryRef key_copied_attributes = NULL;
    CFDataRef key_data = NULL;
    SecKeyRef key_ref = NULL;
    CFStringRef key_type = NULL;
    CFStringRef key_label_ref = NULL;
    CFDataRef application_label_ref = NULL;

    struct aws_array_list decoded_cert_buffer_list;
    AWS_ZERO_STRUCT(decoded_cert_buffer_list);
    struct aws_array_list decoded_key_buffer_list;
    AWS_ZERO_STRUCT(decoded_key_buffer_list);

    /*
     * iOS SecItem requires DER encoded files so we first convert the provided PEM encoded
     * cert and key into a list of aws_pem_object that strips headers/footers and Base64 decodes
     * the data into a byte buf.
     */
    if (aws_pem_objects_init_from_file_contents(&decoded_cert_buffer_list, alloc, *public_cert_chain)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM certificate to DER format.");
        goto done;
    }
    AWS_ASSERT(aws_array_list_is_valid(&decoded_cert_buffer_list));

    if (aws_pem_objects_init_from_file_contents(&decoded_key_buffer_list, alloc, *private_key)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM certificate to DER format.");
        goto done;
    }
    AWS_ASSERT(aws_array_list_is_valid(&decoded_key_buffer_list));

    /*
     * A PEM certificate file could contains multiple PEM data sections. We currently decode and
     * use the first certificate data only. Certificate chaining support could be added for iOS
     * in the future.
     * */
    if (aws_array_list_length(&decoded_cert_buffer_list) > 1) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Certificate chains not currently supported on iOS.");
        result = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    /*
     * The aws_pem_object preserves the type of encoding found in the PEM file. We can use the
     * type_string member to set the appropriate attribute on storage.
     */
    struct aws_pem_object *pem_cert_ptr = NULL;
    aws_array_list_get_at_ptr(&decoded_cert_buffer_list, (void **)&pem_cert_ptr, 0);
    AWS_ASSERT(pem_cert_ptr);

    struct aws_pem_object *pem_key_ptr = NULL;
    aws_array_list_get_at_ptr(&decoded_key_buffer_list, (void **)&pem_key_ptr, 0);
    AWS_ASSERT(pem_key_ptr);

    /* CFDataRef is used to generate the value to pair with kSecValueRef in the SecItemAdd */
    cert_data = CFDataCreate(cf_alloc, pem_cert_ptr->data.buffer, pem_cert_ptr->data.len);
    if (!cert_data) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Error creating certificate data system call.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    key_data = CFDataCreate(cf_alloc, pem_key_ptr->data.buffer, pem_key_ptr->data.len);
    if (!key_data) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Error creating private key data system call.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /* Set the format of the key */
    switch (pem_key_ptr->type) {
        case AWS_PEM_TYPE_PRIVATE_RSA_PKCS1:
            key_type = kSecAttrKeyTypeRSA;
            break;

        case AWS_PEM_TYPE_EC_PRIVATE:
            key_type = kSecAttrKeyTypeEC;
            break;

        case AWS_PEM_TYPE_PRIVATE_PKCS8:
            /* PKCS8 is not supported on iOS/tvOS (the framework doesn't allow it) and is
             * currently NOT supported by us on macOS PKCS8 support for macOS using SecItem
             * can be added later for macOS only but will require a different import strategy
             * than the currently shared one. */
            key_type = kSecAttrKeyTypeRSA;
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "The PKCS8 private key format is currently unsupported for use with SecItem.");
            result = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            goto done;
            break;

        case AWS_PEM_TYPE_UNKNOWN:
        default:
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Unsupported private key format.");
            result = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            goto done;
    }

    /* Attributes used for query and adding of cert/key SecItems */

    /*
     * We create a SecCertificateRef here to use with the kSecValueRef key as well as to
     * extract the serial number for use as a unique identifier when storing the
     * certificate in the keychain. The serial number is also used as the identifier
     * when retrieving the identity
     */
    cert_ref = SecCertificateCreateWithData(cf_alloc, cert_data);
    if (!cert_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating SecCertificateRef from cert_data.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    cert_serial_data = SecCertificateCopySerialNumberData(cert_ref, &error);
    if (error) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed extracting serial number data from cert_ref.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    cert_label_ref = CFStringCreateWithBytes(
        cf_alloc,
        (const UInt8 *)aws_string_bytes(secitem_options->cert_label),
        secitem_options->cert_label->len,
        kCFStringEncodingUTF8,
        false);
    if (!cert_label_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating certificate label.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /*
     * We create a SecKeyRef here to use with the kSecValueRef key as well as to extract
     * the application label for use as a unique identifier when storing the private key
     * in the keychain.
     */
    key_attributes =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, key_type);
    key_ref = SecKeyCreateWithData(key_data, key_attributes, &error);

    // Get the hash of the public key stored within the private key
    key_copied_attributes = SecKeyCopyAttributes(key_ref);
    // application_label_ref gets released when key_copied_attributes is released.
    application_label_ref = (CFDataRef)CFDictionaryGetValue(key_copied_attributes, kSecAttrApplicationLabel);
    if (!application_label_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating private key application label.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    key_label_ref = CFStringCreateWithBytes(
        cf_alloc,
        (const UInt8 *)aws_string_bytes(secitem_options->key_label),
        secitem_options->key_label->len,
        kCFStringEncodingUTF8,
        false);
    if (!key_label_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating private key label.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    // Add the certificate and private key to keychain then retrieve identity
#if !defined(AWS_OS_IOS)
    aws_mutex_lock(&s_sec_mutex);
#endif /* !AWS_OS_IOS */

    if (aws_secitem_add_certificate_to_keychain(cf_alloc, cert_ref, cert_serial_data, cert_label_ref)) {
        goto done;
    }

    if (aws_secitem_add_private_key_to_keychain(cf_alloc, key_ref, key_label_ref, application_label_ref)) {
        goto done;
    }

    if (aws_secitem_get_identity(cf_alloc, cert_serial_data, secitem_identity)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:
#if !defined(AWS_OS_IOS)
    aws_mutex_unlock(&s_sec_mutex);
#endif /* !AWS_OS_IOS */

    // cleanup
    if (error != NULL)
        CFRelease(error);
    if (cert_data != NULL)
        CFRelease(cert_data);
    if (cert_ref != NULL)
        CFRelease(cert_ref);
    if (cert_serial_data != NULL)
        CFRelease(cert_serial_data);
    if (cert_label_ref)
        CFRelease(cert_label_ref);
    if (key_attributes)
        CFRelease(key_attributes);
    if (key_copied_attributes)
        CFRelease(key_copied_attributes);
    if (key_data != NULL)
        CFRelease(key_data);
    if (key_ref != NULL)
        CFRelease(key_ref);
    if (key_type != NULL)
        CFRelease(key_type);
    if (key_label_ref)
        CFRelease(key_label_ref);

    // Zero out the array list and release it
    aws_pem_objects_clean_up(&decoded_cert_buffer_list);
    aws_pem_objects_clean_up(&decoded_key_buffer_list);

    return result;
}

int aws_secitem_import_pkcs12(
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *pkcs12_cursor,
    const struct aws_byte_cursor *password,
    sec_identity_t *out_identity) {

    int result = AWS_OP_ERR;
    CFArrayRef items = NULL;
    CFDataRef pkcs12_data = NULL;
    CFMutableDictionaryRef dictionary = NULL;
    SecIdentityRef sec_identity_ref = NULL;
    CFStringRef password_ref = NULL;
    bool should_release_password = true;

    pkcs12_data = CFDataCreate(cf_alloc, pkcs12_cursor->ptr, pkcs12_cursor->len);
    if (password->len) {
        password_ref = CFStringCreateWithBytes(cf_alloc, password->ptr, password->len, kCFStringEncodingUTF8, false);
    } else {
        should_release_password = false;
        password_ref = CFSTR("");
    }

    dictionary = CFDictionaryCreateMutable(cf_alloc, 0, NULL, NULL);
    CFDictionaryAddValue(dictionary, kSecImportExportPassphrase, password_ref);

    OSStatus status = SecPKCS12Import(pkcs12_data, dictionary, &items);

    if (status != errSecSuccess || CFArrayGetCount(items) == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed to import PKCS#12 file with OSStatus:%d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    // Extract the identity from the first item in the array
    // identity_and_trust does not need to be released as it is not a copy or created CF object.
    CFDictionaryRef identity_and_trust = CFArrayGetValueAtIndex(items, 0);
    sec_identity_ref = (SecIdentityRef)CFDictionaryGetValue(identity_and_trust, kSecImportItemIdentity);

    if (sec_identity_ref != NULL) {
        AWS_LOGF_INFO(
            AWS_LS_IO_PKI, "static: Successfully imported PKCS#12 file into keychain and retrieved identity.");
    } else {
        status = errSecItemNotFound;
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed to retrieve identity from PKCS#12 with OSStatus %d", (int)status);
        goto done;
    }

    *out_identity = sec_identity_create(sec_identity_ref);

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    if (pkcs12_data)
        CFRelease(pkcs12_data);
    if (dictionary)
        CFRelease(dictionary);
    if (should_release_password)
        CFRelease(password_ref);
    if (items)
        CFRelease(items);
    return result;
}

int aws_import_trusted_certificates(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *certificates_blob,
    CFArrayRef *certs) {
    AWS_PRECONDITION(certificates_blob != NULL);

    struct aws_array_list certificates;

    if (aws_pem_objects_init_from_file_contents(&certificates, alloc, *certificates_blob)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: decoding CA PEM failed.");
        aws_array_list_clean_up(&certificates);
        return AWS_OP_ERR;
    }

    size_t cert_count = aws_array_list_length(&certificates);
    CFMutableArrayRef temp_cert_array = CFArrayCreateMutable(cf_alloc, cert_count, &kCFTypeArrayCallBacks);

    int err = AWS_OP_SUCCESS;
    aws_mutex_lock(&s_sec_mutex);
    for (size_t i = 0; i < cert_count; ++i) {
        struct aws_pem_object *pem_object_ptr = NULL;
        aws_array_list_get_at_ptr(&certificates, (void **)&pem_object_ptr, i);

        CFDataRef cert_blob = CFDataCreate(cf_alloc, pem_object_ptr->data.buffer, pem_object_ptr->data.len);

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
    aws_pem_objects_clean_up(&certificates);
    aws_array_list_clean_up(&certificates);
    return err;
}

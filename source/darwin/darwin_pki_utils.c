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

/*
     * Attributes being set:
     * Required for All: We set these automatically with provided cert/key
     * kSecClass: (CFTypeRef) Specifies class of the item
     * kSecValueData: (CFDataRef) Actual data to be stored
     *
     * Required for Keys:
     * kSecAttrKeyType: (CFStringRef) Specifies the type of key. Must be set for keys
     * kSecAttrKeySizeInBits: (CFNumberRef) Specifies the size of the key in bits
     *
     * Optional Attributes that Default to None/NULL.
     * kSecAttrApplicationTag: (CFDataRef) A tag to identify the item. IS used for key uniqueness.
     * kSecAttrService: (CFStringRef) Specifies a service associated with the item. IS used for key uniqueness.
     * kSecAttrLabel: (CFStringRef) A user-readable label for the item. NOT used for key uniqueness.
     * kSecAttrAccount: (CFStringRef) Specifies an account associated with the item. NOT used for key uniqueness.
     * kSecAttrAccessGroup: (CFStringRef) Specifies the access group for keychain sharing
     * kSecAttrEffectiveKeySize: (CFNumberRef) The effective size of the key in bits (not required?)
     *
     * Optional Attributes that have Default values
     * kSecAttrAccessible: (CTFTypeRef) Determines when the item is accessible
     *      Default: kSecAttrAccessibleWhenUnlocked
     * kSecAttrIsPermanent: (CTFBooleanRef) Indicates whether the key should be stored permanently in the keychain
     *      Default: kCFBooleanFalse
     *
     * kSecAttrSynchonizable: (CFBooleanRef) (iOS only) Specifies whether the item is synchronizable with iCloud Keychain
     *      Default: kCFBooleanFalse
     * kSecUseDataProtectionKeychain: (CFBooleanRef) (iOS only) Specifies whether to use the data protection keychain
     *      Default: kCFBooleanTrue. If set to false, the default keychain is used which doesn't take advantage
     *               of additional security features provided by data protection keychains. We may not need to
     *               expose this attribute unless it's specifically requested for some reason.
     *
     * kSecUseKeychain: (macOS only) Specify which keychain to use
     *
     * errSecDuplicateItem: https://developer.apple.com/documentation/security/1542001-security_framework_result_codes/errsecduplicateitem?language=objc
     *
     * Primary Keys: Attributes used to determine errSecDuplicateItem
     * For iOS, both kSecAttrSynchronizable and kSecAttrAccessGroup are primary keys.
     * kSecAttrSynchronizable: (CFBooleanRef) Whether the item is synchronized to other devices through iCloud.
     * Use kSecAttrSynchronizableAny instead of kCFBooleanTrue or kCFBooleanFalse to query for both synchronizable and non-syncrhonizable results.
     * Note: kSecAttrSynchronizableAny can be used with SecItemCopyMatching, SecItemUpdate, and SecItemDelete along with kSecAttrSyncrhonizable key.
     *
     * kSecAttrAccessGroup: (CFStringRef) indicates the item's one and only access group
     * https://developer.apple.com/documentation/security/ksecattraccessgroup?language=objc
     * Naming a group that’s not among the creating app’s access groups—including the empty string, which is always an invalid group—generates an error
     * If you don’t explicitly set a group, keychain services defaults to the app’s first access group, which is either the first keychain access group,
     * or the app ID when the app has no keychain groups.
     * By default, the SecItemUpdate, SecItemDelete, and SecItemCopyMatching methods search all the app’s access groups.
     * Note: This attribute applies to macOS keychain items only if you also set a value of true for the kSecUseDataProtectionKeychain key,
     * the kSecAttrSynchronizable key, or both.
     *
     * for identity items, which are certificate and a private key bundled together, the primary keys are the same as for a certificate.
     * Because a private key may be certified more than once, the uniqueness of the certificate determines that of the identity.
     *
     * Certificate Primary Keys:
     * kSecAttrCertificateType: (CFNumberRef) value indicates the item's certificate type
     *      - values see the CSSM_CERT_TYPE enumeration in cssmtype.h https://opensource.apple.com/source/Security/Security-55471/libsecurity_cssm/lib/cssmtype.h.auto.html
     *      - default will try to add common value such as X.509. We will not pass this attribute and allow default value to be used.
     * kSecAttrIssuer: (CFStringRef) value indicates the item's issuer
     *      - default will try to extract issuer from the certificate itself. We will not pass this attribute and allow default value to be used.
     * kSecAttrSerialNumber: (CFStringRef) value indicates the item's serial number
     *      - default will infer the serial number from the certificate data itself.
     *
     * Key item Primary Keys:
     * kSecAttrKeyClass: (CFTypeRef) value indicates item's cryptographic key class
     *      - values https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values?language=objc#1679052
     *      - relevant to us kSecAttrKeyTypeRSA, ? kSecAttrKeyTypeEC, ? kSecAttrKeyTypeECDSA, ? kSecAttrKeyTypeECSECPrimeRandom
     * kSecAttrKeyType
     * kSecAttrApplicationLabel
     * kSecAttrApplicationTag
     * kSecAttrKeySizeInBits
     * kSecAttrEffectiveKeySize
     *
     * We should have default values set for some optional attributes. Proposed optionals we set listed below:
     * kSecAttrApplicationTag
     * kSecAttrService
     * kSecAttrLabel
     *
     */

// Steve DEBUG temp func to test status of entitlement and print.
void check_keychain_entitlements() {
    printf("Checking Keychain Entitlements\n");
    CFStringRef service = CFSTR("com.example.service");
    const void *keys[] = { kSecClass, kSecReturnAttributes };
    const void *values[] = { kSecClassCertificate, kCFBooleanTrue };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFTypeRef item = NULL;
    OSStatus status = SecItemCopyMatching(query, &item);

    if (status == errSecSuccess) {
        printf("Keychain access successful.\n");
        if (CFDictionaryGetTypeID() == CFGetTypeID(item)) {
            CFShow(item);
        }
    } else if (status == errSecItemNotFound) {
        printf("No keychain item found for the given query.\n");
    } else {
        printf("Keychain access failed with status: %d\n", (int)status);
        switch (status) {
        case errSecMissingEntitlement:
            printf("Error: Missing required entitlements.\n");
            break;
        case errSecAuthFailed:
            printf("Error: Authentication failed.\n");
            break;
        case errSecNotAvailable:
            printf("Error: Keychain not available.\n");
            break;
        default:
            printf("Error: OSStatus %d\n", (int)status);
            break;
        }
    }

    if (item) {
        CFRelease(item);
    }
    CFRelease(query);
}
// Steve DEBUG temp func to print contents of a CFDataRef
void printCFDataRef(CFDataRef data) {
    if (data == NULL) {
        printf("CFDataRef is NULL\n");
        return;
    }

    const UInt8 *dataPtr = CFDataGetBytePtr(data);
    CFIndex dataLength = CFDataGetLength(data);

    printf("CFDataRef contents (length: %ld):\n", dataLength);

    for (CFIndex i = 0; i < dataLength; i++) {
        printf("%02x ", dataPtr[i]);
    }
    printf("\n");
}

int aws_tls_ctx_options_set_certificate_keychain_attributes(
    struct aws_tls_ctx_options *options,
    void *keys[], void *values[], int count) {
#if defined(AWS_OS_IOS)

#else
    // for (int i = 0; i < count; i++) {
    //     if (keys[i] == kSecAttrLabel) {

    //     }
    // }
    (void) keys;
    (void) values;
    (void) count;
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif /* AWS_OS_IOS */
}

AWS_IO_API int aws_tls_ctx_options_set_private_key_keychain_attributes(
    struct aws_tls_ctx_options *options,
    void *keys[], void *values[], int count) {
#if defined(AWS_OS_IOS)

#else
    (void) keys;
    (void) values;
    (void) count;
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);

#endif /* AWS_OS_IOS */
}

int aws_secitem_add_or_update_certificate(
    CFAllocatorRef cf_alloc,
    CFDataRef cert_data,
    CFDataRef serial_data,
    CFStringRef label) {

    /*
     * Attributes
     * kSecClass: (CFTypeRef) Specifies class of the item
     * kSecValueData: (CFDataRef) Data to be stored
     * kSecAttrLabel: We should set this to allow human readable understanding of what the item in the keychain is.
     * kSecAttrSerialNumber: (CFStringRef) We extract this unique identifier from the certificate to use as a key
     */

    int result = AWS_OP_ERR;
    OSStatus status;
    CFDictionaryRef query = NULL;
    CFDictionaryRef attributes = NULL;
    CFTypeRef copy_result = NULL;

    // Query for existing item
    const void *query_keys[] = { kSecClass, kSecAttrLabel, kSecAttrSerialNumber };
    const void *query_values[] = { kSecClassCertificate, label, serial_data };
    query = CFDictionaryCreate(cf_alloc, query_keys, query_values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of certificate search query.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    // Search for existing certificate item in keychain
    status = SecItemCopyMatching(query, &copy_result);
    if (status == errSecItemNotFound) {
        // Item not found, add it
        const void *add_keys[] = { kSecClass, kSecAttrLabel, kSecValueData };
        const void *add_values[] = { kSecClassCertificate, label, cert_data };
        attributes = CFDictionaryCreate(cf_alloc, add_keys, add_values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (attributes == NULL) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of certificate attributes.");
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
        status = SecItemAdd(attributes, NULL);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd certificate failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    } else if (status == errSecSuccess) {
        // Item found, update it
        AWS_LOGF_INFO(
            AWS_LS_IO_PKI,
            "static: keychain contains existing certificate that was previously imported into the Keychain.  "
            "Updating certificate in keychain.");
        const void *update_keys[] = { kSecValueData };
        const void *update_values[] = { cert_data };
        attributes = CFDictionaryCreate(cf_alloc, update_keys, update_values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (attributes == NULL) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of certificate update attributes.");
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
        status = SecItemUpdate(query, attributes);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemUpdate certificate failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    } else {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching certificate failed with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    if (query) CFRelease(query);
    if (attributes) CFRelease(attributes);
    if (copy_result) CFRelease(copy_result);

    return result;
}

int aws_secitem_add_or_update_private_key(
    CFAllocatorRef cf_alloc,
    CFDataRef key_data,
    CFStringRef label) {

    int result = AWS_OP_ERR;
    OSStatus status;
    CFDictionaryRef query = NULL;
    CFDictionaryRef attributes = NULL;
    CFTypeRef copy_result = NULL;

    // Query for existing item
    const void *query_keys[] = { kSecClass, kSecAttrLabel };
    const void *query_values[] = { kSecClassKey, label };
    query = CFDictionaryCreate(cf_alloc, query_keys, query_values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (query == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of certificate search query.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    // Search for existing private key item in keychain
    status = SecItemCopyMatching(query, &copy_result);
    if (status == errSecItemNotFound) {
        // Item not found, add it
        const void *add_keys[] = { kSecClass, kSecAttrLabel, kSecValueData, kSecAttrKeyType, kSecAttrKeyClass };
        const void *add_values[] = { kSecClassKey, label, key_data, kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate };
        attributes = CFDictionaryCreate(cf_alloc, add_keys, add_values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        status = SecItemAdd(attributes, NULL);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd private key failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    } else if (status == errSecSuccess) {
        // Item found, update it
        AWS_LOGF_INFO(
            AWS_LS_IO_PKI,
            "static: keychain contains existing private key that was previously imported into the Keychain.  "
            "Updating private key in keychain.");
        const void *update_keys[] = { kSecValueData };
        const void *update_values[] = { key_data };
        attributes = CFDictionaryCreate(cf_alloc, update_keys, update_values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (attributes == NULL) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of private key update attributes.");
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
        status = SecItemUpdate(query, attributes);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemUpdate private key failed with OSStatus %d", (int)status);
            result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    } else {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching private key failed with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    if (query) CFRelease(query);
    if (attributes) CFRelease(attributes);
    if (copy_result) CFRelease(copy_result);

    return result;
}

int aws_secitem_retrieve_certificate_and_key(
    CFAllocatorRef cf_alloc,
    CFStringRef cert_label,
    CFStringRef key_label,
    SecCertificateRef *certificate,
    SecKeyRef *private_key) {

    int result = AWS_OP_ERR;
    OSStatus status;
    CFDictionaryRef cert_query = NULL;
    CFDictionaryRef key_query = NULL;
    CFTypeRef cert_result = NULL;
    CFTypeRef key_result = NULL;

    // Query for certificate
    const void *cert_keys[] = { kSecClass, kSecAttrLabel, kSecAttrService, kSecReturnRef };
    const void *cert_values[] = { kSecClassCertificate, cert_label, kCFBooleanTrue };
    cert_query = CFDictionaryCreate(cf_alloc, cert_keys, cert_values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (cert_query == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of certificate search query.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    status = SecItemCopyMatching(cert_query, &cert_result);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching certificate failed during retrieval with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    *certificate = (SecCertificateRef)cert_result;

    // Query for private key
    const void *key_keys[] = { kSecClass, kSecAttrLabel, kSecAttrService, kSecReturnRef };
    const void *key_values[] = { kSecClassKey, key_label, kCFBooleanTrue };
    key_query = CFDictionaryCreate(cf_alloc, key_keys, key_values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (key_query == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of private key search query.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    status = SecItemCopyMatching(key_query, &key_result);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching private key failed during retrieval with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    *private_key = (SecKeyRef)key_result;

    result = AWS_OP_SUCCESS;

done:

    if (cert_query) CFRelease(cert_query);
    if (key_query) CFRelease(key_query);
    if (status != errSecSuccess) {
        if (cert_result) CFRelease(cert_result);
        if (key_result) CFRelease(key_result);
    }
    return result;
}

#if !defined(AWS_OS_IOS)

// Function to create identity from certificate and private key via SecItem
int aws_secitem_create_identity(
    CFAllocatorRef cf_alloc,
    CFStringRef cert_label,
    CFStringRef key_label,
    CFStringRef service,
    CFArrayRef *identity) {

    int result = AWS_OP_ERR;
    OSStatus status;
    CFDictionaryRef cert_query = NULL;
    CFDictionaryRef key_query = NULL;
    CFTypeRef cert_result = NULL;
    CFTypeRef key_result = NULL;
    SecCertificateRef certificate = NULL;
    SecKeyRef private_key = NULL;
    SecIdentityRef identity_output;

    // Query for certificate
    const void *cert_keys[] = { kSecClass, kSecAttrLabel, kSecAttrService, kSecReturnRef };
    const void *cert_values[] = { kSecClassCertificate, cert_label, service, kCFBooleanTrue };
    cert_query = CFDictionaryCreate(cf_alloc, cert_keys, cert_values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (cert_query == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of certificate search query.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    status = SecItemCopyMatching(cert_query, &cert_result);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching certificate failed during identity creation with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    certificate = (SecCertificateRef)cert_result;

    // Query for private key
    const void *key_keys[] = { kSecClass, kSecAttrLabel, kSecAttrService, kSecReturnRef };
    const void *key_values[] = { kSecClassKey, key_label, service, kCFBooleanTrue };
    key_query = CFDictionaryCreate(cf_alloc, key_keys, key_values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (key_query == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating CFDictionary of private key search query.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    status = SecItemCopyMatching(key_query, &key_result);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching certificate failed during identity creation with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }
    private_key = (SecKeyRef)key_result;

    // Create identity
    status = SecIdentityCreateWithCertificate(cf_alloc, certificate, &identity_output);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecIdentityCreateWithCertificate failed during identity creation with OSStatus %d", (int)status);
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    CFTypeRef certs[] = {identity_output};
    *identity = CFArrayCreate(cf_alloc, (const void **)certs, 1L, &kCFTypeArrayCallBacks);

    result = AWS_OP_SUCCESS;
done:
    //cleanup
    if (cert_query) CFRelease(cert_query);
    if (key_query) CFRelease(key_query);
    if (cert_result) CFRelease(cert_result);
    if (key_result) CFRelease(key_result);

    return result;
}

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
    check_keychain_entitlements();

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

#if defined(AWS_OS_IOS)

int aws_import_public_and_private_keys_to_identity(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    CFArrayRef *identity,
    const struct aws_secitem_options *secitem_options) {

    AWS_PRECONDITION(public_cert_chain != NULL);
    AWS_PRECONDITION(private_key != NULL);

    // Check current entitlement to keychain status
    check_keychain_entitlements();

    int result = AWS_OP_ERR;

    CFErrorRef error = NULL;
    CFDataRef cert_data = NULL;
    SecCertificateRef cert_ref = NULL;
    CFDataRef serial_data = NULL;
    CFDataRef key_data = NULL;
    CFStringRef cert_label_ref = NULL;
    CFStringRef key_label_ref = NULL;
    struct aws_array_list decoded_cert_buffer_list;
    AWS_ZERO_STRUCT(decoded_cert_buffer_list);
    struct aws_array_list decoded_key_buffer_list;
    AWS_ZERO_STRUCT(decoded_key_buffer_list);

    // STEVE DEBUG Track these to determine whether we need to clean them up.
    SecCertificateRef certificate_retrieved = NULL;
    SecKeyRef private_key_retrieved = NULL;

    // STEVE DEBUG not implemented yet
    CFDataRef root_cert_data = NULL;

    // iOS SecItem requires DER encoded files so we first convert the provided PEM encoded cert and key
    // into a list of aws_pem_object that strips headers/footers and Base64 decodes the data into a byte buf.
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

    // A PEM certificate file could contains multiple PEM data sections. We currently decode and use the first
    // certificate data only. Certificate chaining support could be added for iOS in the future.
    if (aws_array_list_length(&decoded_cert_buffer_list) > 1) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Certificate chains not currently supported on iOS.");
        result = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    // The aws_pem_object preserves the type of encoding found in the PEM file. We can use the type_string
    // member to set the appropriate attribute on storage.
    struct aws_pem_object *pem_cert_ptr = NULL;
    aws_array_list_get_at_ptr(&decoded_cert_buffer_list, (void **)&pem_cert_ptr, 0);
    AWS_ASSERT(pem_cert_ptr);

    struct aws_pem_object *pem_key_ptr = NULL;
    aws_array_list_get_at_ptr(&decoded_key_buffer_list, (void **)&pem_key_ptr, 0);
    AWS_ASSERT(pem_key_ptr);

    // CFDataRef is the expected format from SecItem API for storing or updating items on the keychain
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

    // Attributes

    // We temporarily create a SecCertificateRef here to extract the serial number for use as a
    // unique identifier when storing and updating a certificate in the keychain.
    cert_ref = SecCertificateCreateWithData(cf_alloc, cert_data);
    if (!cert_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating SecCertificateRef from cert_data.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    serial_data = SecCertificateCopySerialNumberData(cert_ref, &error);
    if (error) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed extracting serial number data from cert_ref.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    // STEVE DEBUG print the serial
    // printCFDataRef(serial_data);

    cert_label_ref = CFStringCreateWithBytes(cf_alloc, (const UInt8 *)aws_string_bytes(secitem_options->cert_label), secitem_options->cert_label->len, kCFStringEncodingUTF8, false);
    if (!cert_label_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating certificate label.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    key_label_ref = CFStringCreateWithBytes(cf_alloc, (const UInt8 *)aws_string_bytes(secitem_options->key_label), secitem_options->key_label->len, kCFStringEncodingUTF8, false);
    if (!key_label_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating private key label.");
        result = aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    printf("Attempting to add certificate to keychain\n\n");
    if (aws_secitem_add_or_update_certificate(cf_alloc, cert_data, serial_data, cert_label_ref)) {
        goto done;
    }

    if (aws_secitem_add_or_update_private_key(cf_alloc, key_data, cert_label_ref)){
        goto done;
    }

    if (aws_secitem_retrieve_certificate_and_key(cf_alloc, cert_label_ref, key_label_ref, &certificate_retrieved, &private_key_retrieved)){
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:
    //cleanup
    if (error != NULL) CFRelease(error);
    if (cert_data != NULL) CFRelease(cert_data);
    if (cert_ref != NULL) CFRelease(cert_ref);
    if (serial_data != NULL) CFRelease(serial_data);
    if (key_data != NULL) CFRelease(key_data);
    if (cert_label_ref) CFRelease(cert_label_ref);
    if (key_label_ref) CFRelease(key_label_ref);
    if (root_cert_data != NULL) CFRelease(root_cert_data);

    // Zero out the array list and release it
    aws_pem_objects_clean_up(&decoded_cert_buffer_list);

    return result;
}

#endif /* AWS_OS_IOS */

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

void aws_release_identity(CFArrayRef identity) {
    CFRelease(identity);
}

void aws_release_certificates(CFArrayRef certs) {
    CFRelease(certs);
}

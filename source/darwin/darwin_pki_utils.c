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
#include <TargetConditionals.h>

#include "darwin_shared_private.h"

/* SecureTransport is not thread-safe during identity import */
/* https://developer.apple.com/documentation/security/certificate_key_and_trust_services/working_with_concurrency */
static struct aws_mutex s_sec_mutex = AWS_MUTEX_INIT;

#if !TARGET_OS_IPHONE
#    define AwsSecKeychainRef SecKeychainRef
#else /* TARGET_OS_IPHONE */
/* Among Apple platforms only macOS supports file-based keychain represented by SecKeychainRef type. On iOS, tvOS, and
 * watchOS this type is unavailable. To keep code consistent on all platforms we use void* type when file-based keychain
 * is not available. */
#    define AwsSecKeychainRef void *
#endif /* !TARGET_OS_IPHONE */

void aws_cf_release(CFTypeRef obj) {
    if (obj != NULL) {
        CFRelease(obj);
    }
}

static int s_import_key_into_keychain_with_seckeychain(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *private_key,
    AwsSecKeychainRef import_keychain) {

    (void)alloc;
    (void)cf_alloc;
    (void)private_key;
    (void)import_keychain;

#if !TARGET_OS_IPHONE

    AWS_PRECONDITION(private_key != NULL);
    /* SecItemImport used here for importing private key into keychain requires SecKeychainRef in order to actually put
     * a private key into keychain. */
    AWS_PRECONDITION(import_keychain != NULL);

    int result = AWS_OP_ERR;

    struct aws_array_list decoded_key_buffer_list;
    AWS_ZERO_STRUCT(decoded_key_buffer_list);

    /* Decode PEM format file to DER format */
    if (aws_pem_objects_init_from_file_contents(&decoded_key_buffer_list, alloc, *private_key)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM private key to DER format.");
        goto done;
    }
    AWS_FATAL_ASSERT(aws_array_list_is_valid(&decoded_key_buffer_list));

    /* A PEM file may contain multiple PEM data sections. Try importing each PEM section until we successfully find
     * a key. */
    for (size_t index = 0; index < aws_array_list_length(&decoded_key_buffer_list); index++) {
        struct aws_pem_object *pem_object_ptr = NULL;
        /* We only check individual PEM sections and do not currently support keys with multiple PEM sections. */
        aws_array_list_get_at_ptr(&decoded_key_buffer_list, (void **)&pem_object_ptr, index);
        if (!pem_object_ptr) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to get PEM object at index %zu", index);
            continue;
        }
        CFDataRef key_data = CFDataCreate(cf_alloc, pem_object_ptr->data.buffer, pem_object_ptr->data.len);
        if (!key_data) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Error in creating private key data system call at index %zu", index);
            continue;
        }

        /* Import private key data into keychain. */
        SecExternalFormat format = kSecFormatUnknown;
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
            AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully imported private key into keychain with SecKeychain.");
            result = AWS_OP_SUCCESS;
            break;
        } else {
            // Log the error code for key importing
            AWS_LOGF_WARN(AWS_LS_IO_PKI, "static: Failed to import private key with OSStatus %d", (int)key_status);
        }
    }

done:
    // Zero out the array list and release it
    aws_pem_objects_clean_up(&decoded_key_buffer_list);
    return result;

#else /* TARGET_OS_IPHONE */

    aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    return AWS_OP_ERR;

#endif /* !TARGET_OS_IPHONE */
}

static int s_aws_secitem_add_certificate_to_keychain(
    CFAllocatorRef cf_alloc,
    SecCertificateRef cert_ref,
    CFDataRef serial_data,
    CFDataRef issuer_data,
    CFStringRef label,
    AwsSecKeychainRef import_keychain) {

    (void)import_keychain;

    int result = AWS_OP_ERR;
    OSStatus status;

    CFMutableDictionaryRef add_attributes = NULL;
    CFMutableDictionaryRef delete_query = NULL;

    add_attributes =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(add_attributes, kSecClass, kSecClassCertificate);
    CFDictionaryAddValue(add_attributes, kSecAttrSerialNumber, serial_data);
    CFDictionaryAddValue(add_attributes, kSecAttrIssuer, issuer_data);
    CFDictionaryAddValue(add_attributes, kSecAttrLabel, label);
    CFDictionaryAddValue(add_attributes, kSecValueRef, cert_ref);
#if !TARGET_OS_IPHONE
    /* Target file-based keychain instead of data protection keychain. */
    CFDictionaryAddValue(add_attributes, kSecUseDataProtectionKeychain, kCFBooleanFalse);
    if (import_keychain != NULL) {
        CFDictionaryAddValue(add_attributes, kSecUseKeychain, import_keychain);
    }
#endif // !TARGET_OS_IPHONE

    // Initial attempt to add certificate to keychain.
    status = SecItemAdd(add_attributes, NULL);

    // A duplicate item is handled. All other errors are unhandled.
    if (status != errSecSuccess && status != errSecDuplicateItem) {
        switch (status) {
            case errSecMissingEntitlement:
                AWS_LOGF_ERROR(
                    AWS_LS_IO_PKI,
                    "SecItemAdd certificate failed with OSStatus %d : errSecMissingEntitlement. The process attempting "
                    "to access the keychain is missing the necessary entitlements.",
                    (int)status);
                break;
            default:
                AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd certificate failed with OSStatus %d", (int)status);
                aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
                break;
        }
        goto done;
    }

    /* A duplicate item error indicates the certificate already exists in the keychain. We delete the
     * existing certificate and re-add the certificate in case there are differences that need to be applied.
     *
     * query should be made up of primary keys only. Optional/non-unique attributes in the query
     * can result in not finding the matching certificate and cause the update operation to fail.
     *
     * Certificate item primary keys used for the query:
     * kSecAttrSerialNumber: (CFStringRef) value indicates the item's serial number
     *      - We explicity set this value, extracted from the certificate itself as our primary method of determining
     *        uniqueness of the certificate.
     * kSecAttrIssuer: (CFStringRef) value indicates the item's issuer
     *      - We explicitly set this value, extracted from the certificate itself. This additional primary key will be
     *        used to determine uniqueness of the certificate.
     *
     * Certificate primary keys we do not use for the query:
     * These can be added in the future if we require a more specified search query.
     * kSecAttrCertificateType: (CFNumberRef) value indicates the item's certificate type
     *      - values see the CSSM_CERT_TYPE enumeration in cssmtype.h
     * https://opensource.apple.com/source/Security/Security-55471/libsecurity_cssm/lib/cssmtype.h.auto.html
     *      - default will try to add common value such as X.509. We do not pass this attribute and allow default value
     * to be used. If we decide to support other types of certificates, we should set and use this value explicitly.
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
        CFDictionaryAddValue(delete_query, kSecAttrIssuer, issuer_data);
#if !TARGET_OS_IPHONE
        /* Target file-based keychain instead of data protection keychain. */
        CFDictionaryAddValue(delete_query, kSecUseDataProtectionKeychain, kCFBooleanFalse);
#endif // !TARGET_OS_IPHONE

        // delete the existing certificate from keychain
        status = SecItemDelete(delete_query);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemDelete certificate failed with OSStatus %d", (int)status);
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        // now try adding it again
        status = SecItemAdd(add_attributes, NULL);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd certificate failed with OSStatus %d", (int)status);
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    }

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully imported certificate into SecItem keychain.");

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    aws_cf_release(add_attributes);
    aws_cf_release(delete_query);
    return result;
}

static int s_aws_secitem_add_private_key_to_keychain(
    CFAllocatorRef cf_alloc,
    SecKeyRef key_ref,
    CFStringRef label,
    CFDataRef application_label,
    AwsSecKeychainRef import_keychain) {

    (void)import_keychain;

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
#if !TARGET_OS_IPHONE
    /* Target file-based keychain instead of data protection keychain. */
    CFDictionaryAddValue(add_attributes, kSecUseDataProtectionKeychain, kCFBooleanFalse);
    if (import_keychain != NULL) {
        CFDictionaryAddValue(add_attributes, kSecUseKeychain, import_keychain);
    }
#endif // !TARGET_OS_IPHONE

    // Initial attempt to add private key to keychain.
    status = SecItemAdd(add_attributes, NULL);

    // A duplicate item is handled. All other errors are unhandled.
    if (status != errSecSuccess && status != errSecDuplicateItem) {
        switch (status) {
            case errSecMissingEntitlement:
                AWS_LOGF_ERROR(
                    AWS_LS_IO_PKI,
                    "SecItemAdd private key failed with OSStatus %d : errSecMissingEntitlement. The process attempting "
                    "to access the keychain is missing the necessary entitlements.",
                    (int)status);
                break;
            default:
                AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd private key failed with OSStatus %d", (int)status);
                aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
                break;
        }
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
#if !TARGET_OS_IPHONE
        /* Target file-based keychain instead of data protection keychain. */
        CFDictionaryAddValue(delete_query, kSecUseDataProtectionKeychain, kCFBooleanFalse);
#endif // !TARGET_OS_IPHONE
       // delete the existing private key from keychain
        status = SecItemDelete(delete_query);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemDelete private key failed with OSStatus %d", (int)status);
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        // now try adding it again
        status = SecItemAdd(add_attributes, NULL);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemAdd private key failed with OSStatus %d", (int)status);
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
    }

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully imported private key into keychain with SecItem.");

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    aws_cf_release(add_attributes);
    aws_cf_release(delete_query);

    return result;
}

static int s_aws_secitem_get_identity(
    CFAllocatorRef cf_alloc,
    CFDataRef serial_data,
    CFDataRef issuer_data,
    SecCertificateRef cert_ref,
    sec_identity_t *out_identity,
    AwsSecKeychainRef import_keychain) {

    (void)cert_ref;
    (void)import_keychain;

    int result = AWS_OP_ERR;
    OSStatus status;
    CFMutableDictionaryRef search_query = NULL;
    SecIdentityRef sec_identity_ref = NULL;

    CFArrayRef cert_filter = NULL;
    CFArrayRef keychain_filter = NULL;

    /*
     * SecItem identity is created when a certificate matches a private key in the keychain.
     * Since a private key may be associated with multiple certificates, searching for the
     * identity using a unique attribute of the certificate is required. This is why we use
     * the serial_data and issuer from the certificate as the search parameter.
     */
    search_query =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(search_query, kSecClass, kSecClassIdentity);
    CFDictionaryAddValue(search_query, kSecAttrSerialNumber, serial_data);
    CFDictionaryAddValue(search_query, kSecAttrIssuer, issuer_data);
    CFDictionaryAddValue(search_query, kSecReturnRef, kCFBooleanTrue);

#if !TARGET_OS_IPHONE
    /* Target file-based keychain instead of data protection keychain. */
    CFDictionaryAddValue(search_query, kSecUseDataProtectionKeychain, kCFBooleanFalse);
    /* The kSecAttrSerialNumber filter attribute does not work for kSecClassIdentity when SecItem targets file-based
     * keychain. So, use additional filtering by a certificate provided by a user. */
    cert_filter = CFArrayCreate(cf_alloc, (const void **)&cert_ref, 1L, &kCFTypeArrayCallBacks);
    CFDictionaryAddValue(search_query, kSecMatchItemList, cert_filter);

    if (import_keychain) {
        keychain_filter = CFArrayCreate(cf_alloc, (const void **)&import_keychain, 1L, &kCFTypeArrayCallBacks);
        CFDictionaryAddValue(search_query, kSecMatchSearchList, keychain_filter);
    }
#endif // !TARGET_OS_IPHONE

    /*
     * Copied or created CF items must have CFRelease called on them or you leak memory. This identity needs to
     * have CFRelease called on it at some point or it will leak.
     */
    status = SecItemCopyMatching(search_query, (CFTypeRef *)&sec_identity_ref);

    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "SecItemCopyMatching identity failed with OSStatus %d", (int)status);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    *out_identity = sec_identity_create(sec_identity_ref);
    if (*out_identity == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_PKI, "sec_identity_create failed to create a sec_identity_t from provided SecIdentityRef.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    AWS_LOGF_INFO(AWS_LS_IO_PKI, "static: Successfully retrieved identity from keychain.");

    result = AWS_OP_SUCCESS;

done:
    // cleanup
    aws_cf_release(search_query);
    aws_cf_release(sec_identity_ref);
    aws_cf_release(cert_filter);
    aws_cf_release(keychain_filter);

    return result;
}

/*
 * Look for a private key in PEM data sections.
 * Returns the first private key found.
 */
struct aws_pem_object *s_find_private_key(const struct aws_array_list *pem_objects_list) {
    struct aws_pem_object *pem_object_ptr = NULL;
    for (size_t index = 0; index < aws_array_list_length(pem_objects_list); index++) {
        aws_array_list_get_at_ptr(pem_objects_list, (void **)&pem_object_ptr, index);
        switch (pem_object_ptr->type) {
            case AWS_PEM_TYPE_PRIVATE_RSA_PKCS1:
            case AWS_PEM_TYPE_EVP_PKEY:
            case AWS_PEM_TYPE_EC_PRIVATE:
            case AWS_PEM_TYPE_PRIVATE_PKCS8:
                AWS_LOGF_DEBUG(AWS_LS_IO_PKI, "static: Found a private key in PEM file.");
                return pem_object_ptr;
            default:
                break;
        }
    }
    return NULL;
}

/*
 * Import private key into Apple keychain.
 *
 * macOS:
 *  - imports into file-based keychain.
 *  - supports RSA with a key size of at least 2048 bits.
 *  - supports ECC NIST P-256/P-384/P-521 keys.
 * iOS/tvOS:
 *  - imports into data protection keychain.
 *  - supports RSA with a key size of at least 2048 bits.
 */
int s_import_private_key_into_keychain(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *private_key,
    const struct aws_secitem_options *secitem_options,
    AwsSecKeychainRef import_keychain) {

    int result = AWS_OP_ERR;

    struct aws_array_list decoded_key_buffer_list;
    AWS_ZERO_STRUCT(decoded_key_buffer_list);

    struct aws_pem_object *pem_key_ptr = NULL;

    CFDictionaryRef key_copied_attributes = NULL;
    CFMutableDictionaryRef key_attributes = NULL;
    SecKeyRef key_ref = NULL;
    CFDataRef key_data = NULL;
    CFDataRef application_label_ref = NULL;
    CFStringRef key_type = NULL;
    CFStringRef key_label_ref = NULL;
    CFErrorRef error = NULL;

    /*
     * SecItem requires DER encoded files so we first convert the provided PEM encoded
     * cert and key into a list of aws_pem_object that strips headers/footers and Base64 decodes
     * the data into a byte buf.
     */
    if (aws_pem_objects_init_from_file_contents(&decoded_key_buffer_list, alloc, *private_key)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM private key to DER format.");
        goto done;
    }
    AWS_ASSERT(aws_array_list_is_valid(&decoded_key_buffer_list));

    pem_key_ptr = s_find_private_key(&decoded_key_buffer_list);
    if (!pem_key_ptr) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to find a private key in PEM file.");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    /*
     * The aws_pem_object preserves the type of encoding found in the PEM file. We use the type_string member to set the
     * appropriate CFStringRef key_type attribute.
     */
    switch (pem_key_ptr->type) {
        case AWS_PEM_TYPE_PRIVATE_RSA_PKCS1:
            key_type = kSecAttrKeyTypeRSA;
            break;

        case AWS_PEM_TYPE_EC_PRIVATE:
            key_type = kSecAttrKeyTypeEC;
#if TARGET_OS_IPHONE
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: The ECC private key format is currently unsupported for use on iOS or tvOS");
            aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            goto done;
#endif
            break;

        case AWS_PEM_TYPE_PRIVATE_PKCS8:
            /*
             * PKCS8 is not supported on iOS/tvOS (the framework doesn't allow it) and is currently NOT supported by us
             * on macOS PKCS8 support for macOS using SecItem can be added later for macOS only but will require a
             * different import strategy than the currently shared one.
             */
            key_type = kSecAttrKeyTypeRSA;
#if TARGET_OS_IPHONE
            AWS_LOGF_ERROR(
                AWS_LS_IO_PKI, "static: The PKCS8 private key format is currently unsupported for use with SecItem");
            aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            goto done;
#endif
            break;

        default:
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Unsupported private key format %d", (int)pem_key_ptr->type);
            aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            goto done;
    }

    key_data = CFDataCreate(cf_alloc, pem_key_ptr->data.buffer, pem_key_ptr->data.len);
    if (!key_data) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Error creating private key data system call.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /*
     * We create a SecKeyRef (key_ref) here using the key_data for the purpose of extracting the public key hash from
     * the private key. We need the public key hash (application_label_ref) to use as a unique identifier when importing
     * the private key into the keychain.
     */
    key_attributes =
        CFDictionaryCreateMutable(cf_alloc, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, key_type);

    /*
     * Try to parse a user-provided private key into a SecKeyRef. On this step, the private key won't be added
     * to keychain yet.
     */
    key_ref = SecKeyCreateWithData(key_data, key_attributes, &error);
    if (error) {
        char description_buffer[256];
        aws_get_core_foundation_error_description(error, description_buffer, sizeof(description_buffer));
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed importing private key using SecItem: %s", description_buffer);

#if TARGET_OS_IPHONE
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
#endif

        /*
         * If parsing with SecItem fails, we fall back to trying to add the private key via SecKeychain API.
         * This API is available on macOS only.
         */
        AWS_LOGF_DEBUG(AWS_LS_IO_PKI, "static: Falling back to SecKeychain API for private key import");
        if (s_import_key_into_keychain_with_seckeychain(alloc, cf_alloc, private_key, import_keychain)) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed importing private key into keychain with SecKeychain API");
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }
        result = AWS_OP_SUCCESS;
    } else {
        /*
         * Get the hash of the public key stored within the private key by extracting it from the key_ref's attributes
         */
        key_copied_attributes = SecKeyCopyAttributes(key_ref);

        /*
         * application_label_ref does not need to be released. It gets released when key_copied_attributes is released.
         */
        application_label_ref = (CFDataRef)CFDictionaryGetValue(key_copied_attributes, kSecAttrApplicationLabel);
        if (!application_label_ref) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed creating private key application label.");
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        key_label_ref = CFStringCreateWithBytes(
            cf_alloc,
            (const UInt8 *)aws_string_bytes(secitem_options->key_label),
            secitem_options->key_label->len,
            kCFStringEncodingUTF8,
            false);
        if (!key_label_ref) {
            AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed creating private key label.");
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            goto done;
        }

        if (s_aws_secitem_add_private_key_to_keychain(
                cf_alloc, key_ref, key_label_ref, application_label_ref, import_keychain)) {
            aws_mutex_unlock(&s_sec_mutex);
            goto done;
        }

        result = AWS_OP_SUCCESS;
    }

done:
    aws_cf_release(key_attributes);
    aws_cf_release(key_copied_attributes);
    aws_cf_release(key_type);
    aws_cf_release(key_label_ref);
    aws_cf_release(key_data);
    aws_cf_release(key_ref);
    aws_pem_objects_clean_up(&decoded_key_buffer_list);

    return result;
}

int aws_secitem_import_cert_and_key(
    struct aws_allocator *alloc,
    CFAllocatorRef cf_alloc,
    const struct aws_byte_cursor *public_cert_chain,
    const struct aws_byte_cursor *private_key,
    sec_identity_t *secitem_identity,
    const struct aws_secitem_options *secitem_options,
    const struct aws_string *keychain_path) {

    AWS_PRECONDITION(public_cert_chain != NULL);
    AWS_PRECONDITION(private_key != NULL);

    int result = AWS_OP_ERR;

    CFErrorRef error = NULL;
    CFDataRef cert_data = NULL;
    SecCertificateRef cert_ref = NULL;
    CFDataRef cert_serial_data = NULL;
    CFDataRef cert_issuer_data = NULL;
    CFStringRef cert_label_ref = NULL;
    AwsSecKeychainRef import_keychain = NULL;

    struct aws_array_list decoded_cert_buffer_list;
    AWS_ZERO_STRUCT(decoded_cert_buffer_list);

#if !TARGET_OS_IPHONE
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wdeprecated-declarations"

    /*
     * SecKeychain functions are marked as deprecated. There are no non-deprecated functions for specifying specific
     * file-based keychains.
     * Disable compiler warnings for now. This will be removed when we stop supporting file-based keychain altogether.
     */
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

#else  /* TARGET_OS_IPHONE */
    if (keychain_path) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Keychain path is supported only on macOS");
        result = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }
#endif /* !TARGET_OS_IPHONE */

    /*
     * SecItem requires DER encoded files so we first convert the provided PEM encoded
     * cert and key into a list of aws_pem_object that strips headers/footers and Base64 decodes
     * the data into a byte buf.
     */
    if (aws_pem_objects_init_from_file_contents(&decoded_cert_buffer_list, alloc, *public_cert_chain)) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "static: Failed to decode PEM certificate to DER format.");
        goto done;
    }
    AWS_ASSERT(aws_array_list_is_valid(&decoded_cert_buffer_list));

    /*
     * A PEM certificate file could contain multiple PEM data sections. We currently decode and
     * use the first certificate data only. Certificate chaining support could be added in the future.
     */
    if (aws_array_list_length(&decoded_cert_buffer_list) > 1) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Certificate chains not currently supported on iOS.");
        result = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    /* Convert the DER encoded files to the CFDataRef type required for import into keychain */
    struct aws_pem_object *pem_cert_ptr = NULL;
    aws_array_list_get_at_ptr(&decoded_cert_buffer_list, (void **)&pem_cert_ptr, 0);
    AWS_ASSERT(pem_cert_ptr);

    cert_data = CFDataCreate(cf_alloc, pem_cert_ptr->data.buffer, pem_cert_ptr->data.len);
    if (!cert_data) {
        AWS_LOGF_WARN(AWS_LS_IO_PKI, "Error creating certificate data system call.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /* Attributes used for query and adding of cert/key SecItems */

    /*
     * We create a SecCertificateRef here to use with the kSecValueRef key as well as to extract the serial number and
     * issuer for use as a unique identifier when storing the certificate in the keychain. The serial number and issuer
     * are also used as the identifier when retrieving the identity
     */
    cert_ref = SecCertificateCreateWithData(cf_alloc, cert_data);
    if (!cert_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating SecCertificateRef from cert_data.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    cert_serial_data = SecCertificateCopySerialNumberData(cert_ref, &error);
    if (error) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed extracting serial number data from cert_ref.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    cert_issuer_data = SecCertificateCopyNormalizedIssuerSequence(cert_ref);

    cert_label_ref = CFStringCreateWithBytes(
        cf_alloc,
        (const UInt8 *)aws_string_bytes(secitem_options->cert_label),
        secitem_options->cert_label->len,
        kCFStringEncodingUTF8,
        false);
    if (!cert_label_ref) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed creating certificate label.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    /* Add the certificate and private key to keychain then retrieve identity.
     * Protect the entire SecItem operation with mutex to prevent race conditions. */
    aws_mutex_lock(&s_sec_mutex);

    if (s_import_private_key_into_keychain(alloc, cf_alloc, private_key, secitem_options, import_keychain)) {
        aws_mutex_unlock(&s_sec_mutex);
        goto done;
    }

    if (s_aws_secitem_add_certificate_to_keychain(
            cf_alloc, cert_ref, cert_serial_data, cert_issuer_data, cert_label_ref, import_keychain)) {
        aws_mutex_unlock(&s_sec_mutex);
        goto done;
    }

    if (s_aws_secitem_get_identity(
            cf_alloc, cert_serial_data, cert_issuer_data, cert_ref, secitem_identity, import_keychain)) {
        aws_mutex_unlock(&s_sec_mutex);
        goto done;
    }

    aws_mutex_unlock(&s_sec_mutex);

    result = AWS_OP_SUCCESS;

done:
    /* cleanup */
    aws_cf_release(error);
    aws_cf_release(cert_data);
    aws_cf_release(cert_ref);
    aws_cf_release(cert_serial_data);
    aws_cf_release(cert_issuer_data);
    aws_cf_release(cert_label_ref);

    /* Zero out the array list and release it */
    aws_pem_objects_clean_up(&decoded_cert_buffer_list);

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

    pkcs12_data = CFDataCreate(cf_alloc, pkcs12_cursor->ptr, pkcs12_cursor->len);
    if (!pkcs12_data) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Error creating pkcs12 data system call.");
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto done;
    }

    if (password->len) {
        password_ref = CFStringCreateWithBytes(cf_alloc, password->ptr, password->len, kCFStringEncodingUTF8, false);
    } else {
        password_ref = CFStringCreateWithCString(cf_alloc, "", kCFStringEncodingUTF8);
    }

    dictionary = CFDictionaryCreateMutable(cf_alloc, 0, NULL, NULL);
    CFDictionaryAddValue(dictionary, kSecImportExportPassphrase, password_ref);

    OSStatus status = SecPKCS12Import(pkcs12_data, dictionary, &items);

    if (status != errSecSuccess || CFArrayGetCount(items) == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_PKI, "Failed to import PKCS#12 file with OSStatus:%d", (int)status);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
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
    aws_cf_release(pkcs12_data);
    aws_cf_release(dictionary);
    aws_cf_release(password_ref);
    aws_cf_release(items);
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

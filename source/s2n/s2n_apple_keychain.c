/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifdef __APPLE__

#    include <aws/common/encoding.h>
#    include <aws/common/logging.h>
#    include <aws/io/logging.h>
#    include <aws/io/pem.h>
#    include <s2n.h>

#    include <Security/Security.h>

static bool s_is_cert_trusted(const SecCertificateRef cert) {
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    if (!policy) {
        AWS_LOGF_ERROR(AWS_LS_IO_TLS, "Failed to create a basic X509 SecPolicy");
        return false;
    }

    bool is_trusted = false;

    SecTrustRef trust = NULL;
    OSStatus status = SecTrustCreateWithCertificates(cert, policy, &trust);
    if (status == errSecSuccess) {
        is_trusted = SecTrustEvaluateWithError(trust, NULL);
    } else {
        AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Failed to create a trust object, status code %d", (int)status);
    }

    CFRelease(policy);
    if (trust) {
        CFRelease(trust);
    }

    return is_trusted;
}

static bool s_cert_has_basic_constraints_ca(SecCertificateRef cert) {
    CFErrorRef error = NULL;
    CFArrayRef keys = CFArrayCreate(NULL, (const void *[]){kSecOIDBasicConstraints}, 1, &kCFTypeArrayCallBacks);

    CFDictionaryRef values = SecCertificateCopyValues(cert, keys, &error);
    CFRelease(keys);
    if (!values) {
        if (error) {
            CFRelease(error);
        }
        return false;
    }

    bool is_ca = false;
    CFDictionaryRef bc_dict = CFDictionaryGetValue(values, kSecOIDBasicConstraints);
    if (!bc_dict) {
        goto done;
    }

    CFArrayRef bc_section = CFDictionaryGetValue(bc_dict, kSecPropertyKeyValue);
    if (!bc_section) {
        goto done;
    }

    CFIndex count = CFArrayGetCount(bc_section);
    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef entry = CFArrayGetValueAtIndex(bc_section, i);
        CFStringRef label = CFDictionaryGetValue(entry, kSecPropertyKeyLabel);
        CFStringRef value = CFDictionaryGetValue(entry, kSecPropertyKeyValue);
        if (label && value && CFStringCompare(label, CFSTR("Certificate Authority"), 0) == kCFCompareEqualTo &&
            CFStringCompare(value, CFSTR("Yes"), 0) == kCFCompareEqualTo) {
            is_ca = true;
            break;
        }
    }

done:
    CFRelease(values);
    return is_ca;
}

/* This function loads trusted root CA certificates from the macOS searchable keychains into the s2n config.
 * NOTE: Certificates from SystemRootCertificates.keychain are NOT processed here since s2n-tls will get them from the
 * bundle system roots instead. */
int aws_tls_s2n_load_macos_keychain_root_cas(struct s2n_config *config, struct aws_allocator *alloc) {
    CFMutableDictionaryRef query =
        CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    CFArrayRef results = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&results);
    CFRelease(query);

    if (status != errSecSuccess || !results) {
        return AWS_OP_SUCCESS;
    }

    CFIndex count = CFArrayGetCount(results);
    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(results, i);

        CFDataRef subject_data = SecCertificateCopyNormalizedSubjectSequence(cert);
        CFDataRef issuer_data = SecCertificateCopyNormalizedIssuerSequence(cert);

        if (!subject_data || !issuer_data) {
            if (subject_data) {
                CFRelease(subject_data);
            }
            if (issuer_data) {
                CFRelease(issuer_data);
            }
            continue;
        }

        CFStringRef summary = SecCertificateCopySubjectSummary(cert);
        if (summary) {
            char buf[256];
            CFStringGetCString(summary, buf, sizeof(buf), kCFStringEncodingUTF8);
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Processing cert from keychain with subject: %s", buf);
            CFRelease(summary);
        }

        bool is_self_signed = CFEqual(subject_data, issuer_data);
        bool is_ca = s_cert_has_basic_constraints_ca(cert);

        CFRelease(subject_data);
        CFRelease(issuer_data);

        if (!is_self_signed && !is_ca) {
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Cert is not a root");
            continue;
        }

        if (!s_is_cert_trusted(cert)) {
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Cert is not trusted");
            continue;
        }

        CFDataRef cert_data = SecCertificateCopyData(cert);
        if (!cert_data) {
            continue;
        }

        struct aws_byte_cursor der_cursor =
            aws_byte_cursor_from_array(CFDataGetBytePtr(cert_data), (size_t)CFDataGetLength(cert_data));

        struct aws_byte_buf pem_buf;
        if (aws_der_cert_to_pem(alloc, der_cursor, &pem_buf) == AWS_OP_SUCCESS) {
            if (s2n_config_add_pem_to_trust_store(config, (const char *)pem_buf.buffer) == S2N_SUCCESS) {
                AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Added certificate to trust store");
            } else {
                AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Failed to add certificate to trust store");
            }
            aws_byte_buf_clean_up(&pem_buf);
        } else {
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Failed to convert DER to PEM");
        }
        CFRelease(cert_data);
    }

    CFRelease(results);
    return AWS_OP_SUCCESS;
}

#else  /* __APPLE__ */

int aws_tls_s2n_load_macos_keychain_root_cas(struct s2n_config *config, struct aws_allocator *alloc) {
    (void)config;
    (void)alloc;
    AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: Importing certificates from keychain only supported on Apple.");
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}
#endif /* __APPLE__ */

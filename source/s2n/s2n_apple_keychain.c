/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "s2n_apple_keychain.h"

#include <aws/common/encoding.h>
#include <aws/common/error.h>
#include <aws/common/logging.h>
#include <aws/io/logging.h>
#include <aws/io/pem.h>

/* Check for USE_S2N needed to handle cross-compilation for Apple non-macOS platforms that can't use s2n-tls. */
#if defined(__APPLE__) && defined(USE_S2N)

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
void aws_tls_s2n_load_macos_keychain_root_cas(struct s2n_config *config, struct aws_allocator *alloc) {
    CFMutableDictionaryRef query =
        CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    CFArrayRef results = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&results);
    CFRelease(query);

    if (status != errSecSuccess || !results) {
        return;
    }

    /* Check all certificates in the keychains, and if they are trusted root CAs, add them to s2n trust store. */
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

        bool is_self_signed = CFEqual(subject_data, issuer_data);
        bool is_ca = s_cert_has_basic_constraints_ca(cert);

        CFRelease(subject_data);
        CFRelease(issuer_data);

        /* We check both conditions: a root CA is typically self-signed (subject == issuer), but some cross-signed CAs
         * have a different issuer yet are still valid CAs per Basic Constraints. Either condition is sufficient to
         * consider the certificate as a CA worth loading. */
        if (!is_self_signed && !is_ca) {
            continue;
        }

        /* Even if a certificate is a CA, it may have been explicitly distrusted by the user or system. Only proceed if
         * macOS trust evaluation confirms the certificate is trusted. */
        if (!s_is_cert_trusted(cert)) {
            continue;
        }

        CFDataRef cert_data = SecCertificateCopyData(cert);
        if (!cert_data) {
            continue;
        }

        struct aws_byte_cursor der_cursor =
            aws_byte_cursor_from_array(CFDataGetBytePtr(cert_data), (size_t)CFDataGetLength(cert_data));

        CFStringRef summary = SecCertificateCopySubjectSummary(cert);
        const char *cert_summary = "(unknown)";
        char *name_buf = NULL;
        if (summary) {
            CFIndex len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(summary), kCFStringEncodingUTF8) + 1;
            name_buf = aws_mem_calloc(alloc, 1, (size_t)len);
            if (name_buf && CFStringGetCString(summary, name_buf, len, kCFStringEncodingUTF8)) {
                cert_summary = name_buf;
            }
        }

        struct aws_string *pem_str = aws_der_cert_to_pem(alloc, der_cursor);
        if (!pem_str) {
            AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "Failed to convert DER to PEM for certificate '%s'", cert_summary);
        } else if (s2n_config_add_pem_to_trust_store(config, (const char *)pem_str->bytes)) {
            AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "Failed to add certificate '%s' to trust store", cert_summary);
        } else {
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "Successfully added certificate '%s' to s2n trust store", cert_summary);
        }

        aws_string_destroy(pem_str);
        aws_mem_release(alloc, name_buf);
        if (summary) {
            CFRelease(summary);
        }

        CFRelease(cert_data);
    }

    CFRelease(results);
}

#endif /* defined(__APPLE__) && defined(USE_S2N) */

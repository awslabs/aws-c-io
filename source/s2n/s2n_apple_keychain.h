#ifndef AWS_IO_S2N_APPLE_KEYCHAIN_H
#define AWS_IO_S2N_APPLE_KEYCHAIN_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

struct aws_allocator;
struct s2n_config;

/* Loads trusted root CA certificates from the macOS searchable keychains into the s2n config. Certificates from
 * SystemRootCertificates.keychain are NOT processed here since s2n-tls will get them from the bundle system roots
 * instead. */
void aws_tls_s2n_load_macos_keychain_root_cas(struct s2n_config *config, struct aws_allocator *alloc);

#endif /* AWS_IO_S2N_APPLE_KEYCHAIN_H */

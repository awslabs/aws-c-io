#ifndef AWS_IO_TLS_CHANNEL_HANDLER_PRIVATE_H
#define AWS_IO_TLS_CHANNEL_HANDLER_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>

AWS_EXTERN_C_BEGIN

#ifdef _WIN32
/**
 * Force to use schannel creds. Default to false.
 * For windows build above WINDOWS_BUILD_1809, we have deprecated CHANNEL_CREDS.
 * Set the value to true to force to use CHANNEL_CREDS.
 */
AWS_IO_API void aws_windows_force_schannel_creds(bool use_schannel_creds);
#endif

AWS_EXTERN_C_END
#endif /* AWS_IO_TLS_CHANNEL_HANDLER_PRIVATE_H */

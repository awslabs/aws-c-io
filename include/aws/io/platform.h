/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_PLATFORM_H
#define AWS_IO_PLATFORM_H

/* iOS and tvOS should use both AWS_USE_DISPATCH_QUEUE and AWS_USE_SECITEM. */
#if defined(AWS_OS_IOS) || defined(AWS_OS_TVOS)
#   define AWS_USE_DISPATCH_QUEUE
#   define AWS_USE_SECITEM
#endif /* AWS_OS_IOS || AWS_OS_TVOS */

/* macOS can use either kqueue or dispatch queue but defaults to AWS_USE_KQUEUE unless explicitly
 * instructed otherwise. In the event that AWS_USE_DISPATCH_QUEUE is defined on macOS, it will take
 * precedence over AWS_USE_KQUEUE */
#if defined(AWS_OS_MACOS)
#   define AWS_USE_KQUEUE
#endif /* AWS_OS_MACOS */

#endif /* AWS_IO_PLATFORM_H */

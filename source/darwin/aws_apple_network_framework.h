#ifndef AWS_IO_PRIVATE_AWS_APPLE_NETWORK_FRAMEWORK_H
#define AWS_IO_PRIVATE_AWS_APPLE_NETWORK_FRAMEWORK_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/io/tls_channel_handler.h>

/* This Header will only be compiled on Apple Platforms where therse are available. */
#include <Security/Security.h>
#include <dispatch/dispatch.h>

struct secure_transport_ctx {
    struct aws_tls_ctx ctx;
    CFAllocatorRef wrapped_allocator;
    CFArrayRef certs;
    sec_identity_t secitem_identity;
    CFArrayRef ca_cert;
    enum aws_tls_versions minimum_tls_version;
    struct aws_string *alpn_list;
    bool verify_peer;
};

struct dispatch_loop;
struct dispatch_loop_context;

struct dispatch_loop {
    struct aws_allocator *allocator;
    dispatch_queue_t dispatch_queue;
    struct aws_task_scheduler scheduler;
    struct aws_linked_list local_cross_thread_tasks;
    struct aws_event_loop *base_loop;

    /* Apple dispatch queue uses the id string to identify the dispatch queue */
    struct aws_string *dispatch_queue_id;

    /* Synced data handle cross thread tasks and events, and event loop operations*/
    struct {
        struct aws_linked_list cross_thread_tasks;
        struct dispatch_loop_context *context;
        bool suspended;
    } synced_task_data;

    /* Synced thread data handles the thread related info. `is_executing` flag and `current_thread_id` together are used
     * to identify the executing thread id for dispatch queue. See `static bool s_is_on_callers_thread(struct
     * aws_event_loop *event_loop)` for details.
     */
    struct {

        struct aws_mutex thread_data_lock;
        bool is_executing;
        aws_thread_id_t current_thread_id;
    } synced_thread_data;

    bool is_destroying;
};

#endif /* #ifndef AWS_IO_PRIVATE_AWS_APPLE_NETWORK_FRAMEWORK_H  */

#ifndef AWS_IO_PRIVATE_AWS_APPLE_NETWORK_FRAMEWORK_H
#define AWS_IO_PRIVATE_AWS_APPLE_NETWORK_FRAMEWORK_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/tls_channel_handler.h>

#ifdef AWS_OS_APPLE
/* It's ok to include external headers because this is a PRIVATE header file */
#    include <Security/Security.h>
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

#endif /* AWS_OS_APPLE */

#ifdef AWS_USE_DISPATCH_QUEUE

#    include <aws/common/mutex.h>
#    include <aws/common/thread.h>
#    include <dispatch/dispatch.h>

struct dispatch_scheduling_state {
    // Let's us skip processing an iteration task if one is already in the middle
    // of executing
    bool is_executing_iteration;

    // List<scheduled_service_entry> in sorted order by timestamp
    //
    // When we go to schedule a new iteration, we check here first to see
    // if our scheduling attempt is redundant
    struct aws_linked_list scheduled_services;
};

struct dispatch_loop {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    dispatch_queue_t dispatch_queue;
    struct aws_task_scheduler scheduler;
    struct aws_linked_list local_cross_thread_tasks;

    // Apple dispatch queue uses the id string to identify the dispatch queue
    struct aws_string *dispatch_queue_id;

    struct {
        struct dispatch_scheduling_state scheduling_state;
        struct aws_linked_list cross_thread_tasks;
        struct aws_mutex lock;
        bool suspended;
        // `is_executing` flag and `current_thread_id` together are used to identify the excuting
        // thread id for dispatch queue. See `static bool s_is_on_callers_thread(struct aws_event_loop *event_loop)`
        // for details.
        bool is_executing;
        aws_thread_id_t current_thread_id;
    } synced_data;

    bool wakeup_schedule_needed;
    bool is_destroying;
};
#endif /* AWS_USE_DISPATCH_QUEUE */

#endif /* #ifndef AWS_IO_PRIVATE_AWS_APPLE_NETWORK_FRAMEWORK_H  */

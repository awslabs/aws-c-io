#ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H
#define AWS_IO_DARWIN_DISPATCH_QUEUE_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <Security/Security.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/io/tls_channel_handler.h>
#include <dispatch/dispatch.h>

struct secure_transport_ctx {
    struct aws_tls_ctx ctx;
    CFAllocatorRef wrapped_allocator;
    CFArrayRef certs;
    SecIdentityRef secitem_identity;
    CFArrayRef ca_cert;
    enum aws_tls_versions minimum_version;
    struct aws_string *alpn_list;
    bool verify_peer;
};

struct dispatch_scheduling_state {
    /**
     * List<scheduled_service_entry> in sorted order by timestamp
     *
     * When we go to schedule a new iteration, we check here first to see
     * if our scheduling attempt is redundant
     */
    struct aws_linked_list scheduled_services;
};

struct dispatch_loop;
struct dispatch_loop_context;

struct dispatch_loop {
    struct aws_allocator *allocator;
    dispatch_queue_t dispatch_queue;
    struct aws_task_scheduler scheduler;
    struct aws_event_loop *base_loop;

    /*
     * Internal ref-counted dispatch loop context to processing Apple Dispatch Queue Resources.
     * The context keep track of the live status of the dispatch loop. Dispatch queue should be
     * nulled out in context when it is cleaned up.
     */
    struct dispatch_loop_context *context;

    /* Synced data handle cross thread tasks and events, and event loop operations*/
    struct {
        struct aws_mutex lock;
        /*
         * `is_executing` flag and `current_thread_id` together are used
         * to identify the executing thread id for dispatch queue. See `static bool s_is_on_callers_thread(struct
         * aws_event_loop *event_loop)` for details.
         */
        bool is_executing;
        // once suspended is set to true, event loop will no longer schedule any future services entry (the running
        // iteration will still be finished.).
        bool suspended;
        aws_thread_id_t current_thread_id;

        struct aws_linked_list cross_thread_tasks;
    } synced_cross_thread_data;

    bool is_destroying;
};

#endif /* #ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H */

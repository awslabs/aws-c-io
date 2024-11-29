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
     * Let's us skip processing an iteration task if one is already in the middle of executing
     */
    bool will_schedule;

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
    struct aws_ref_count ref_count;
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

#endif /* #ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H */

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
        /**
         * This lock is used to protect synced_data across the threads. It should be acquired whenever data in the
         * synced_data struct is accessed or modified.
         */
        struct aws_mutex synced_data_lock;
        /*
         * `is_executing` flag and `current_thread_id` together are used
         * to identify the executing thread id for dispatch queue. See `static bool s_is_on_callers_thread(struct
         * aws_event_loop *event_loop)` for details.
         */
        bool is_executing;
        aws_thread_id_t current_thread_id;

        /*
         * Set to true when `stop()` is called on event loop. Once suspended is set to true, underlying dispatch queue
         * is set to suspend and event loop will no longer schedule any future service entries. If an iteration block is
         * running it will continue till it finishes. `run()` must be called on a suspended dispatch queue event loop to
         * schedule an iteration block.
         */
        bool suspended;

        /*
         * Will be true when the underlying dispatch_queue is both suspended and has completed running any in progress
         * iteration block. `run()` must be called to resume the event loop and its underlying dispatch queue to
         * schedule an iteration block.
         */
        bool stopped;

        struct aws_linked_list cross_thread_tasks;
    } synced_data;

    bool is_destroying;
};

#endif /* #ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H */

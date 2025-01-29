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
         * `is_executing` flag and `current_thread_id` are used together to identify the thread id of the dispatch queue
         * running the current block. See dispatch queue's `s_is_on_callers_thread()` implementation for details.
         */
        bool is_executing;
        aws_thread_id_t current_thread_id;

        /*
         * Will be true if dispatch queue is in a suspended state. A dispatch queue in a suspended state will not start
         * any blocks that are already enqueued but will not prevent additional blocks from being queued.
         *
         * Set to true when `stop()` is called on event loop.
         * `run()` must be called on owning event_loop to resume processing of blocks on a suspended dispatch queue.
         *
         * Calling dispatch_sync() on a suspended dispatch queue will deadlock.
         */
        bool suspended;

        /*
         * Will be true when the underlying dispatch_queue has completed running all enqueued blocks and no futher work
         * is enqueued.
         */
        bool stopped;

        /*
         * Will be true when dispatch loop has entered state where it is being destroyed.
         */
        bool is_destroying;

        struct aws_linked_list cross_thread_tasks;
    } synced_data;
};

#endif /* #ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H */

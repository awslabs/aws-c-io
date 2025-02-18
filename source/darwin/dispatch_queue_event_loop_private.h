#ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H
#define AWS_IO_DARWIN_DISPATCH_QUEUE_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <Security/Security.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/io/tls_channel_handler.h>
#include <dispatch/dispatch.h>

enum aws_dispatch_loop_execution_state {
    AWS_DLES_SUSPENDED,
    AWS_DLES_RUNNING,
    AWS_DLES_SHUTTING_DOWN,
    AWS_DLES_TERMINATED
};

struct aws_dispatch_loop {
    struct aws_allocator *allocator;
    dispatch_queue_t dispatch_queue;
    struct aws_task_scheduler scheduler;
    struct aws_event_loop *base_loop;
    struct aws_event_loop_group *base_elg;

    struct aws_ref_count ref_count;

    /* Synced data handle cross thread tasks and events, and event loop operations*/
    struct {
        /**
         * The lock is used to protect synced_data across the threads. It should be acquired whenever we touched the
         * data in this synced_data struct.
         */
        struct aws_mutex synced_data_lock;

        /*
         * Allows blocking waits for changes in synced data state.  Currently used by the external destruction process
         * to wait for the loop to enter the TERMINATED state.  It is acceptable to do a blocking wait because
         * event loop group destruction is done in a dedicated thread spawned only for that purpose.
         */
        struct aws_condition_variable signal;

        /*
         * `is_executing` flag and `current_thread_id` are used together to identify the thread id of the dispatch queue
         * running the current block. See dispatch queue's `s_is_on_callers_thread()` implementation for details.
         */
        bool is_executing;
        aws_thread_id_t current_thread_id;

        enum aws_dispatch_loop_execution_state execution_state;

        struct aws_linked_list cross_thread_tasks;

        /*
         * priority queue of <scheduled_iteration_entry> in sorted order by timestamp. Each scheduled_iteration_entry
         * represents a block ALREADY SCHEDULED on Apple dispatch queue.
         *
         * When we schedule a new run iteration, scheduled_iterations is checked to see if the scheduling attempt is
         * redundant.
         */
        // TODO: this can be a linked list
        struct aws_priority_queue scheduled_iterations;
    } synced_data;
};

#endif /* #ifndef AWS_IO_DARWIN_DISPATCH_QUEUE_H */

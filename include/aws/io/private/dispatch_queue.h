#ifndef AWS_IO_PRIVATE_DISPATCH_QUEUE_H
#define AWS_IO_PRIVATE_DISPATCH_QUEUE_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

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

    struct {
        struct dispatch_scheduling_state scheduling_state;
        struct aws_linked_list cross_thread_tasks;
        struct aws_mutex lock;
        bool suspended;
    } synced_data;

    bool wakeup_schedule_needed;
};

#endif /* #ifndef AWS_IO_PRIVATE_DISPATCH_QUEUE_H */

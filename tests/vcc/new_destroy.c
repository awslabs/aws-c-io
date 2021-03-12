/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/* clang-format off */
#include "preamble.h"

/* VCC change: clock fnptr */
int aws_event_loop_init_base(struct aws_event_loop *loop, struct aws_allocator *allocator, aws_io_clock_fn_ptr clock)
    _(writes &loop->alloc)
    _(writes &loop->clock)
    _(maintains \wrapped(allocator))
    _(ensures \result == 0 <==> loop->alloc == allocator && loop->clock->\valid)
;

/* Cleans up hash-table (but not modeled) */
void aws_event_loop_clean_up_base(struct aws_event_loop *loop)
    _(writes \extent(loop))
    _(ensures \mutable(loop))
;

void close(int fd)
    _(requires valid_fd(fd))
;

const struct aws_thread_options *aws_default_thread_options(void)
    _(ensures \wrapped(\result))
;

struct aws_event_loop_vtable s_vtable;

#if USE_EFD
enum
  {
    EFD_SEMAPHORE = 1,
#define EFD_SEMAPHORE EFD_SEMAPHORE
    EFD_CLOEXEC = 02000000,
#define EFD_CLOEXEC EFD_CLOEXEC
    EFD_NONBLOCK = 04000
#define EFD_NONBLOCK EFD_NONBLOCK
  };
int eventfd(unsigned int initval, int flags);
#else
int aws_open_nonblocking_posix_pipe(/*int pipe_fds[2]*/int *pipe_fds)
    _(writes \extent((int[2]) pipe_fds))
    _(ensures \extent_mutable((int[2]) pipe_fds))
    _(ensures \result == AWS_OP_SUCCESS <==>
              valid_fd(pipe_fds[0]) && valid_fd(pipe_fds[1]))
;
#endif

struct aws_event_loop *aws_event_loop_new_default(struct aws_allocator *alloc, aws_io_clock_fn_ptr clock
    _(out \claim(c_mutex))
) {
    /* VCC change: rewrite struct initialization */
#if 0
    struct aws_event_loop_options options = {
        .thread_options = NULL,
        .clock = clock,
    };
#else
    struct aws_event_loop_options options;
    options.thread_options = NULL;
    options.clock = clock;
    _(wrap(&options))
#endif

    /* VCC change: rewrite return to allow for unwrap */
#if 0
    return aws_event_loop_new_default_with_options(alloc, &options);
#else
    struct aws_event_loop *r = aws_event_loop_new_default_with_options(alloc, &options, _(out c_mutex));
    _(unwrap(&options))
    return r;
#endif
}

struct aws_event_loop *aws_event_loop_new_default_with_options(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options
    _(out \claim(c_mutex))
) {
    AWS_PRECONDITION(options);
    /* VCC change: rewrite clock fnptr validity check */
#if 0
    AWS_PRECONDITION(options->clock);
#else
    AWS_PRECONDITION(options->clock->\valid);
#endif

    struct aws_event_loop *loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));
    if (!loop) {
        return NULL;
    }

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing edge-triggered epoll", (void *)loop);
    if (aws_event_loop_init_base(loop, alloc, options->clock)) {
        goto clean_up_loop;
    }

    struct epoll_loop *epoll_loop = aws_mem_calloc(alloc, 1, sizeof(struct epoll_loop));
    if (!epoll_loop) {
        goto cleanup_base_loop;
    }

    if (options->thread_options) {
        epoll_loop->thread_options = *options->thread_options;
    } else {
        epoll_loop->thread_options = *aws_default_thread_options();
    }

    /* initialize thread id to NULL, it should be updated when the event loop thread starts. */
    aws_atomic_init_ptr(&epoll_loop->running_thread_id, NULL);

    aws_linked_list_init(&epoll_loop->task_pre_queue);
    epoll_loop->task_pre_queue_mutex = (struct aws_mutex)AWS_MUTEX_INIT;
    aws_atomic_init_ptr(&epoll_loop->stop_task_ptr, NULL);

    epoll_loop->epoll_fd = epoll_create(100);
    if (epoll_loop->epoll_fd < 0) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to open epoll handle.", (void *)loop);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up_epoll;
    }

    if (aws_thread_init(&epoll_loop->thread_created_on, alloc)) {
        goto clean_up_epoll;
    }

#if USE_EFD
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Using eventfd for cross-thread notifications.", (void *)loop);
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (fd < 0) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to open eventfd handle.", (void *)loop);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up_thread;
    }

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: eventfd descriptor %d.", (void *)loop, fd);
    epoll_loop->write_task_handle = (struct aws_io_handle){.data.fd = fd, .additional_data = NULL};
    epoll_loop->read_task_handle = (struct aws_io_handle){.data.fd = fd, .additional_data = NULL};
#else
    AWS_LOGF_DEBUG(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Eventfd not available, falling back to pipe for cross-thread notification.",
        (void *)loop);

    /* VCC change: array init using {0} */
#if 0
    int pipe_fds[2] = {0};
#else
    int pipe_fds[2];
    pipe_fds[0] = 0; pipe_fds[1] = 0;
#endif
    /* this pipe is for task scheduling. */
    if (aws_open_nonblocking_posix_pipe(pipe_fds)) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: failed to open pipe handle.", (void *)loop);
        goto clean_up_thread;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP, "id=%p: pipe descriptors read %d, write %d.", (void *)loop, pipe_fds[0], pipe_fds[1]);
    epoll_loop->write_task_handle.data.fd = pipe_fds[1];
    epoll_loop->read_task_handle.data.fd = pipe_fds[0];
#endif

    if (aws_task_scheduler_init(&epoll_loop->scheduler, alloc)) {
        goto clean_up_pipe;
    }

    epoll_loop->should_continue = false;

    loop->impl_data = epoll_loop;
    loop->vtable = &s_vtable;

    _(wrap(&epoll_loop->task_pre_queue.head))
    _(wrap(&epoll_loop->task_pre_queue.tail))
    _(wrap(&epoll_loop->task_pre_queue))
    epoll_loop->task_pre_queue_mutex.locked = 0;
    _(ghost {
        epoll_loop->task_pre_queue_mutex.protected_obj = &epoll_loop->task_pre_queue;
        epoll_loop->task_pre_queue_mutex.\owns = {&epoll_loop->task_pre_queue};
        _(wrap(&epoll_loop->task_pre_queue_mutex))
        c_mutex = \make_claim({&epoll_loop->task_pre_queue_mutex}, epoll_loop->task_pre_queue_mutex.\closed);
    })
    _(wrap(&epoll_loop->write_task_handle))
    _(wrap(&epoll_loop->scheduler.timed_queue))
    _(wrap(&epoll_loop->scheduler.timed_list.head))
    _(wrap(&epoll_loop->scheduler.timed_list.tail))
    _(wrap(&epoll_loop->scheduler.timed_list))
    _(wrap(&epoll_loop->scheduler.asap_list.head))
    _(wrap(&epoll_loop->scheduler.asap_list.tail))
    _(wrap(&epoll_loop->scheduler.asap_list))
    _(wrap(&epoll_loop->scheduler))
    _(wrap(&epoll_loop->thread_created_on))
    _(wrap(&epoll_loop->running_thread_id))
    _(wrap(&epoll_loop->read_task_handle))
    _(wrap(&epoll_loop->stop_task.node))
    _(wrap(&epoll_loop->stop_task.priority_queue_node))
    _(wrap(&epoll_loop->stop_task))
    _(wrap(&epoll_loop->stop_task_ptr))
    _(wrap(epoll_loop::scheduler))
    _(wrap(epoll_loop::read_handle))
    _(wrap(epoll_loop::stop_task))
    _(wrap(epoll_loop::queue))
    _(wrap(epoll_loop::status))
    _(wrap(epoll_loop))
    _(wrap(loop))
    return loop;

clean_up_pipe:
#if USE_EFD
    close(epoll_loop->write_task_handle.data.fd);
    epoll_loop->write_task_handle.data.fd = -1;
    epoll_loop->read_task_handle.data.fd = -1;
#else
    close(epoll_loop->read_task_handle.data.fd);
    close(epoll_loop->write_task_handle.data.fd);
#endif

clean_up_thread:
    aws_thread_clean_up(&epoll_loop->thread_created_on);

clean_up_epoll:
    if (epoll_loop->epoll_fd >= 0) {
        close(epoll_loop->epoll_fd);
    }

    aws_mem_release(alloc, epoll_loop);

cleanup_base_loop:
    aws_event_loop_clean_up_base(loop);

clean_up_loop:
    aws_mem_release(alloc, loop);

    return NULL;
}

/* Fake-up call to s_stop since this is just a vtable lookup */
#define aws_event_loop_stop(event_loop) \
    s_stop(event_loop _(ghost c_event_loop) _(ghost c_mutex));

static void s_destroy(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex))
) {
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying event_loop", (void *)event_loop);

    struct epoll_loop *epoll_loop = event_loop->impl_data;

    /* we don't know if stop() has been called by someone else,
     * just call stop() again and wait for event-loop to finish. */
    aws_event_loop_stop(event_loop);
    s_wait_for_stop_completion(event_loop _(ghost c_event_loop) _(ghost c_mutex));
    epoll_loop = event_loop->impl_data; /*< VCC change: refresh epoll_loop reference */
    _(unwrap(event_loop))
    _(unwrap(epoll_loop))
    _(assert epoll_loop->task_pre_queue_mutex.\claim_count == 1)
    _(ghost \destroy_claim(c_mutex, {&epoll_loop->task_pre_queue_mutex}))
    _(assert epoll_loop->task_pre_queue_mutex.\claim_count == 0)
    _(assert \wrapped0(&epoll_loop->task_pre_queue_mutex))
    _(assert epoll_loop->task_pre_queue_mutex.locked == 0)
    _(assert \inv(&epoll_loop->task_pre_queue_mutex))
    _(unwrap(&epoll_loop->task_pre_queue_mutex))
    _(assert \wrapped(&epoll_loop->task_pre_queue))

    /* setting this so that canceled tasks don't blow up when asking if they're on the event-loop thread. */
    epoll_loop->thread_joined_to = aws_thread_current_thread_id();
    _(unwrap &epoll_loop->running_thread_id)
    aws_atomic_store_ptr(&epoll_loop->running_thread_id, &epoll_loop->thread_joined_to);
    _(wrap &epoll_loop->running_thread_id)
    aws_task_scheduler_clean_up(&epoll_loop->scheduler);

    while (!aws_linked_list_empty(&epoll_loop->task_pre_queue))
        _(invariant 0 <= epoll_loop->task_pre_queue.length)
        _(invariant \wrapped(&epoll_loop->task_pre_queue))
        _(writes &epoll_loop->task_pre_queue)
    {
        _(ghost struct aws_task *t)
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&epoll_loop->task_pre_queue _(out t));
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    _(unwrap(&epoll_loop->thread_created_on))
    aws_thread_clean_up(&epoll_loop->thread_created_on);

    _(unwrap(&epoll_loop->read_task_handle))
    _(unwrap(&epoll_loop->write_task_handle))
#if USE_EFD
    close(epoll_loop->write_task_handle.data.fd);
    epoll_loop->write_task_handle.data.fd = -1;
    epoll_loop->read_task_handle.data.fd = -1;
#else
    close(epoll_loop->read_task_handle.data.fd);
    close(epoll_loop->write_task_handle.data.fd);
#endif

    close(epoll_loop->epoll_fd);
    /* successively unwrap epoll for imminent free() */
    _(unwrap
        epoll_loop::scheduler,
        &epoll_loop->scheduler,
        &epoll_loop->running_thread_id,
        epoll_loop::read_handle,
        epoll_loop::stop_task,
        &epoll_loop->stop_task,
        epoll_loop::queue,
        &epoll_loop->task_pre_queue,
        epoll_loop::status)
    _(unwrap
        &epoll_loop->scheduler.timed_queue,
        &epoll_loop->scheduler.timed_list,
        &epoll_loop->scheduler.asap_list,
        &epoll_loop->stop_task.node,
        &epoll_loop->stop_task.priority_queue_node,
        &epoll_loop->stop_task_ptr,
        &epoll_loop->task_pre_queue.head,
        &epoll_loop->task_pre_queue.tail)
    _(unwrap
        &epoll_loop->scheduler.timed_list.head,
        &epoll_loop->scheduler.timed_list.tail,
        &epoll_loop->scheduler.asap_list.head,
        &epoll_loop->scheduler.asap_list.tail)
    aws_mem_release(event_loop->alloc, epoll_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}
/* clang-format on */

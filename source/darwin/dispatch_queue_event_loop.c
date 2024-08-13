/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>

#include <aws/common/atomics.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/logging.h>

#include <unistd.h>

#include <Block.h>
#include <dispatch/dispatch.h>
#include <dispatch/queue.h>

static void s_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);
static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task);
static int s_connect_to_dispatch_queue(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static void s_free_io_event_resources(void *user_data) {
    (void)user_data;
}
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);

static struct aws_event_loop_vtable s_vtable = {
    .destroy = s_destroy,
    .run = s_run,
    .stop = s_stop,
    .wait_for_stop_completion = s_wait_for_stop_completion,
    .schedule_task_now = s_schedule_task_now,
    .schedule_task_future = s_schedule_task_future,
    .cancel_task = s_cancel_task,
    .register_style.connect_to_completion_port = s_connect_to_dispatch_queue,
    .event_loop_style = AWS_EVENT_LOOP_STYLE_COMPLETION_PORT_BASED,
    .unsubscribe_from_io_events = s_unsubscribe_from_io_events,
    .free_io_event_resources = s_free_io_event_resources,
    .is_on_callers_thread = s_is_on_callers_thread,
};

struct dispatch_loop {
    dispatch_queue_t dispatch_queue;
    struct aws_task_scheduler scheduler;
    aws_thread_id_t running_thread_id;

    struct {
        bool suspended;
        struct aws_mutex lock;
    } sync_data;
    bool wakeup_schedule_needed;
};

static void s_finalize(void* context)
{
    struct aws_event_loop* event_loop = context;
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_clean_up(&dispatch_loop->sync_data.lock);
    aws_mem_release(event_loop->alloc, dispatch_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

/* Setup a dispatch_queue with a scheduler. */
struct aws_event_loop *aws_event_loop_new_dispatch_queue_with_options(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options) {
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->clock);

    struct aws_event_loop *loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing dispatch_queue event-loop", (void *)loop);
    if (aws_event_loop_init_base(loop, alloc, options->clock)) {
        goto clean_up_loop;
    }

    struct dispatch_loop *dispatch_loop = aws_mem_calloc(alloc, 1, sizeof(struct dispatch_loop));

    dispatch_loop->dispatch_queue =
        dispatch_queue_create("com.amazonaws.commonruntime.eventloop", DISPATCH_QUEUE_SERIAL);
    if (!dispatch_loop->dispatch_queue) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to create dispatch queue.", (void *)loop);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up_dispatch;
    }

    aws_task_scheduler_init(&dispatch_loop->scheduler, alloc);
    dispatch_loop->wakeup_schedule_needed = true;
    aws_mutex_init(&dispatch_loop->sync_data.lock);

    loop->impl_data = dispatch_loop;
    loop->vtable = &s_vtable;

    /* The following code is an equivalent of the next commented out section. The difference is, async_and_wait
     * runs in the callers thread, NOT the event-loop's thread and so we need to use the blocks API.
    dispatch_async_and_wait(dispatch_loop->dispatch_queue, ^{
         dispatch_loop->running_thread_id = aws_thread_current_thread_id();
    }); */
    // dispatch_block_t block = dispatch_block_create(0, ^{
      //   dispatch_loop->running_thread_id = aws_thread_current_thread_id();
    // });
    // dispatch_async(dispatch_loop->dispatch_queue, block);
    // dispatch_block_wait(block, DISPATCH_TIME_FOREVER);
    // Block_release(block);

    dispatch_set_context(dispatch_loop->dispatch_queue, loop);
    // Definalizer will be called on dispatch queue ref drop to 0
    dispatch_set_finalizer_f(dispatch_loop->dispatch_queue, &s_finalize);


    return loop;

clean_up_dispatch:
    if (dispatch_loop->dispatch_queue) {
        dispatch_release(dispatch_loop->dispatch_queue);
    }

    aws_mem_release(alloc, dispatch_loop);
    aws_event_loop_clean_up_base(loop);

clean_up_loop:
    aws_mem_release(alloc, loop);

    return NULL;
}

static void s_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying event_loop", (void *)event_loop);

    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    /* make sure the loop is running so we can schedule a last task. */
    s_run(event_loop);

    /* cancel outstanding tasks */
    dispatch_async_and_wait(dispatch_loop->dispatch_queue, ^{
      dispatch_loop->running_thread_id = 0;
      aws_task_scheduler_clean_up(&dispatch_loop->scheduler);
    });

    /* we don't want it stopped while shutting down. dispatch_release will fail on a suspended loop. */
        dispatch_release(dispatch_loop->dispatch_queue);
    }

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    (void)event_loop;

    return AWS_OP_SUCCESS;
}

static int s_run(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->sync_data.lock);
    if (dispatch_loop->sync_data.suspended) {
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);
        dispatch_resume(dispatch_loop->dispatch_queue);
        dispatch_loop->sync_data.suspended = false;
    }
    aws_mutex_unlock(&dispatch_loop->sync_data.lock);

    return AWS_OP_SUCCESS;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->sync_data.lock);
    if (!dispatch_loop->sync_data.suspended) {
        dispatch_loop->sync_data.suspended = true;
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);
        dispatch_suspend(dispatch_loop->dispatch_queue);
    }
    aws_mutex_unlock(&dispatch_loop->sync_data.lock);

    return AWS_OP_SUCCESS;
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: scheduling task %p in-thread for timestamp %llu",
        (void *)event_loop,
        (void *)task,
        (unsigned long long)run_at_nanos);

    dispatch_async(
        dispatch_loop->dispatch_queue,
        /* note: this runs in the dispatch_queue's thread, not the calling thread */
        ^{
          if (run_at_nanos) {
              aws_task_scheduler_schedule_future(&dispatch_loop->scheduler, task, run_at_nanos);
          } else {
              aws_task_scheduler_schedule_now(&dispatch_loop->scheduler, task);
          }

          uint64_t next_task_time = 0;
          /* we already know it has tasks, we just scheduled one. We just want the next run time. */
          aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, &next_task_time);

          /* On the hot path, "run now" tasks get scheduled at a very high rate. Let's avoid scheduling wakeups
           * that we don't need to schedule. the wakeup_schedule_needed flag is toggled after any given task run
           * if the scheduler goes idle AND the "run at" time was zero.*/
          if (next_task_time == 0 && !dispatch_loop->wakeup_schedule_needed) {
              return;
          }

          uint64_t now = 0;
          aws_event_loop_current_clock_time(event_loop, &now);
          /* now schedule a wakeup for that time. */
          dispatch_after(next_task_time - now, dispatch_loop->dispatch_queue, ^{
            if (aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, NULL)) {
                aws_event_loop_register_tick_start(event_loop);
                                /* this ran on a timer, so next_task_time should be the current time when this block executes */
                               aws_task_scheduler_run_all(&dispatch_loop->scheduler, next_task_time);
                aws_event_loop_register_tick_end(event_loop);
            }

            /* try not to wake up the dispatch_queue if we don't have to. If it was a "run now" task, we likely
             * hit this multiple times on the same event-loop tick or scheduled multiples reentrantly. Let's prevent
             * scheduling more wakeups than we need. If they're scheduled in the future, nothing simple we can do
             * and honestly, those aren't really the hot path anyways. */
            if (run_at_nanos == 0 && !aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, NULL)) {
                dispatch_loop->wakeup_schedule_needed = true;
            } else if (run_at_nanos == 0) {
                dispatch_loop->wakeup_schedule_needed = false;
            }
          });
        });
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */);
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: cancelling task %p", (void *)event_loop, (void *)task);
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    dispatch_async(dispatch_loop->dispatch_queue, ^{
      aws_task_scheduler_cancel_task(&dispatch_loop->scheduler, task);
    });
}

static int s_connect_to_dispatch_queue(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_PRECONDITION(handle->set_queue && handle->clear_queue);

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: subscribing to events on handle %p",
        (void *)event_loop,
        (void *)handle->data.handle);
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;
    handle->set_queue(handle, dispatch_loop->dispatch_queue);

    return AWS_OP_SUCCESS;
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: un-subscribing from events on handle %p",
        (void *)event_loop,
        (void *)handle->data.handle);
    handle->clear_queue(handle);
    return AWS_OP_SUCCESS;
}

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    return true;
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    /* this will need to be updated, after we go through design discussion on it. */
    return dispatch_loop->running_thread_id == 0 || dispatch_loop->running_thread_id == aws_thread_current_thread_id();
}

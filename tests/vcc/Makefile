VCC?=vcc
VCC_ARGS+=/sm
GIT?=git
NO_CHANGE_EXPECTED_HASH=754ba168f
NO_CHANGE_FILE=source/linux/epoll_event_loop.c

# The VCC proofs in this directory are based on a snapshot of
# epoll_event_loop.c. This target fails if the source file has changed, in
# which case the proof results may no longer be valid.
.phony: .no_change
.no_change:
	cd ../.. && $(GIT) diff --quiet $(NO_CHANGE_EXPECTED_HASH) $(NO_CHANGE_FILE)

.phony: .proofs
.proofs:
	$(VCC) $(VCC_ARGS) preamble.h
	$(VCC) $(VCC_ARGS) subscribe.c /f:s_subscribe_to_io_events
	$(VCC) $(VCC_ARGS) unsubscribe.c /f:s_unsubscribe_from_io_events
	$(VCC) $(VCC_ARGS) schedule.c /f:s_schedule_task_common /f:s_schedule_task_now /f:s_schedule_task_future
	$(VCC) $(VCC_ARGS) cancel_task.c /f:s_cancel_task
	$(VCC) $(VCC_ARGS) is_on_callers_thread.c /f:s_is_on_callers_thread
	$(VCC) $(VCC_ARGS) process_task_pre_queue.c /f:s_process_task_pre_queue
	$(VCC) $(VCC_ARGS) lifecycle.c /f:s_stop_task /f:s_stop /f:s_wait_for_stop_completion /f:s_run
	$(VCC) $(VCC_ARGS) main_loop.c /f:s_on_tasks_to_schedule /f:s_main_loop
	$(VCC) $(VCC_ARGS) new_destroy.c /f:aws_event_loop_new_default
	$(VCC) $(VCC_ARGS) new_destroy.c /f:aws_event_loop_new_default_with_options /f:s_destroy /p:"-DUSE_EFD=0"
	$(VCC) $(VCC_ARGS) new_destroy.c /f:aws_event_loop_new_default_with_options /f:s_destroy /p:"-DUSE_EFD=1"
	$(VCC) $(VCC_ARGS) client.c /f:test_new_destroy /f:test_subscribe_unsubscribe

.phony: all
all: .no_change .proofs

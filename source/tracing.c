/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/private/tracing.h>

__itt_domain *io_tracing_domain;
__itt_string_handle *tracing_stream_read_handle;
__itt_string_handle *tracing_event_loop_run_tasks;
__itt_string_handle *tracing_event_loop_event_callback;
__itt_string_handle *tracing_event_loop_event_callbacks;

void aws_io_tracing_init() {
    io_tracing_domain = __itt_domain_create("aws.c.io");
    tracing_stream_read_handle = __itt_string_handle_create("InputStreamRead");
    tracing_event_loop_run_tasks = __itt_string_handle_create("EventLoopRunTasks");
    tracing_event_loop_event_callback = __itt_string_handle_create("IOEvent");
    tracing_event_loop_event_callbacks = __itt_string_handle_create("IOEvents");
}

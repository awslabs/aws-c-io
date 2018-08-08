#ifndef AWS_IO_PIPE_H
#define AWS_IO_PIPE_H

/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/common.h>
#include <aws/io/exports.h>

struct aws_event_loop;

struct aws_pipe_read_end {
    void *impl_data;
};

struct aws_pipe_write_end {
    void *impl_data;
};

typedef void(aws_pipe_on_read_end_closed_fn)(struct aws_pipe_read_end *read_end, void *user_data);
typedef void(aws_pipe_on_write_end_closed_fn)(struct aws_pipe_write_end *write_end, void *user_data);
typedef void(aws_pipe_on_read_event_fn)(struct aws_pipe_read_end *pipe, int events, void *user_data);
typedef void(aws_pipe_on_write_complete_fn)(struct aws_pipe_write_end *pipe, int write_result, void *user_data);

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_pipe_open(
    struct aws_pipe_read_end *read_end,
    struct aws_event_loop *read_end_event_loop,
    struct aws_pipe_write_end *write_end,
    struct aws_event_loop *write_end_event_loop,
    struct aws_allocator *allocator);

AWS_IO_API struct aws_event_loop *aws_pipe_get_read_end_event_loop(const struct aws_pipe_read_end *read_end);
AWS_IO_API struct aws_event_loop *aws_pipe_get_write_end_event_loop(const struct aws_pipe_write_end *write_end);

// everything below this line must be called from the event-loop's thread

AWS_IO_API int aws_pipe_close_read_end(
    struct aws_pipe_read_end *read_end,
    aws_pipe_on_read_end_closed_fn *on_closed,
    void *user_data);

AWS_IO_API int aws_pipe_close_write_end(
    struct aws_pipe_write_end *write_end,
    aws_pipe_on_write_end_closed_fn *on_closed,
    void *user_data);

AWS_IO_API int aws_pipe_write(
    struct aws_pipe_write_end *write_end,
    const uint8_t *src,
    size_t src_size,
    aws_pipe_on_write_complete_fn *on_complete,
    void *user_data);

AWS_IO_API int aws_pipe_read(struct aws_pipe_read_end *read_end, uint8_t *dst, size_t dst_size, size_t *num_bytes_read);

AWS_IO_API int aws_pipe_subscribe_to_read_events(
    struct aws_pipe_read_end *read_end,
    aws_pipe_on_read_event_fn *on_read_event,
    void *user_data);

AWS_IO_API int aws_pipe_unsubscribe_from_read_events(struct aws_pipe_read_end *read_end);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_PIPE_H */

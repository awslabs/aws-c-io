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

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop))
) {
    _(assert \always_by_claim(c_event_loop, event_loop))
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    _(assert \always_by_claim(c_event_loop, epoll_loop))
    _(assert \inv(epoll_loop))

    aws_thread_id_t *thread_id = aws_atomic_load_ptr(&epoll_loop->running_thread_id);
    _(assume \thread_local(thread_id))
    _(assume thread_id == NULL || *thread_id == \addr(event_loop->\owner))

    return thread_id && aws_thread_thread_id_equal(*thread_id, aws_thread_current_thread_id());
}
/* clang-format on */

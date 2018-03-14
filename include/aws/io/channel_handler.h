#ifndef AWS_IO_CHANNEL_HANDLER_H
#define AWS_IO_CHANNEL_HANDLER_H

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

#include <aws/io/channel.h>

struct aws_channel_handler;

struct aws_channel_type_tag {
    const char *type_name;
};

struct aws_channel_handler_vtable {
    struct aws_channel_type_tag type_tag;
    size_t vtable_size;

    void (*destroy)(struct aws_channel_handler *handler);
    int (*process_input_messages)(struct aws_channel_handler *handler, struct aws_channel *channel,
            aws_message_queue *queue, int8_t end_of_chain);
    int (*process_output_messages)(struct aws_channel_handler *handler, struct aws_channel *channel,
            aws_message_queue *queue);

    /**
     * handle the shutdown. If the shutdown should terminate with this handler, return 0, otherwise return a shutdown reason
     * if you translate the shutdown into something the handler understands, feel free to return that shutdown reason, otherwise,
     * pass the shutdown reason through.
     */
    int (*handle_channel_shutdown)(struct aws_channel_handler *handler, struct aws_channel *channel, int shutdown_reason);
};

struct aws_channel_handler {
    struct aws_channel_handler_vtable vtable;
    struct aws_allocator *alloc;
    aws_message_queue input_queue;
    aws_message_queue output_queue;
    int8_t can_process_more_input;
    int8_t can_process_more_output;
};

#ifdef __cplusplus
extern "C" {
#endif
AWS_IO_API int aws_channel_handler_init_base(struct aws_channel_handler *channel_handler, struct aws_allocator *alloc);
AWS_IO_API void aws_channel_handler_clean_up_base(struct aws_channel_handler *channel_handler);
AWS_IO_API void aws_channel_handler_destroy(struct aws_channel_handler *channel_handler);
AWS_IO_API int aws_channel_handler_process_input(struct aws_channel_handler *channel_handler,
                                struct aws_channel *channel, aws_message_queue *queue, int8_t is_end_of_chain);
AWS_IO_API int aws_channel_handler_process_output(struct aws_channel_handler *channel_handler,
            struct aws_channel *channel, aws_message_queue *queue);
AWS_IO_API int aws_channel_handler_handle_channel_shutdown(struct aws_channel_handler *handler,
                                                           struct aws_channel *channel, int shutdown_reason);

#ifdef __cplusplus
}
#endif

static inline aws_message_queue * aws_channel_handler_get_input_queue(struct aws_channel_handler *channel_handler) {
    return &channel_handler->input_queue;
}

static inline aws_message_queue * aws_channel_handler_get_output_queue(struct aws_channel_handler *channel_handler) {
    return &channel_handler->output_queue;
}

static inline int8_t aws_channel_handler_can_process_input(struct aws_channel_handler *channel_handler) {
    return channel_handler->can_process_more_input;
}

static inline int8_t aws_channel_handler_can_process_output(struct aws_channel_handler *channel_handler) {
    return channel_handler->can_process_more_output;
}


#endif /* AWS_IO_CHANNEL_HANDLER_H */

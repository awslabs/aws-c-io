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

#include <aws/io/channel_handler.h>

int aws_channel_handler_init_base(struct aws_channel_handler *channel_handler, struct aws_allocator *alloc) {
    channel_handler->can_process_more_input = 1;
    channel_handler->can_process_more_output = 1;
    channel_handler->alloc = alloc;
    aws_linked_list_init(&channel_handler->input_queue);
    aws_linked_list_init(&channel_handler->output_queue);

    return AWS_OP_SUCCESS;
}

void aws_channel_handler_clean_up_base(struct aws_channel_handler *channel_handler) {
    aws_linked_list_empty(&channel_handler->input_queue);
    aws_linked_list_empty(&channel_handler->output_queue);
    channel_handler->can_process_more_input = 0;
    channel_handler->can_process_more_output = 0;
}

void aws_channel_handler_destroy(struct aws_channel_handler *channel_handler) {
    channel_handler->vtable.destroy(channel_handler);
}

int aws_channel_handler_process_input(struct aws_channel_handler *channel_handler,
                                      struct aws_channel *channel, aws_message_queue *queue, int8_t end_of_chain) {
    return channel_handler->vtable.process_input_messages(channel_handler, channel, queue, end_of_chain);
}

int aws_channel_handler_process_output(struct aws_channel_handler *channel_handler,
                                       struct aws_channel *channel, aws_message_queue *queue) {
    return channel_handler->vtable.process_output_messages(channel_handler, channel, queue);
}

int aws_channel_handler_handle_channel_shutdown(struct aws_channel_handler *handler,
                                                struct aws_channel *channel, int shutdown_reason) {
    return handler->vtable.handle_channel_shutdown(handler, channel, shutdown_reason);
}

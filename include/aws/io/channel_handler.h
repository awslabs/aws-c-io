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

/**
 * Virtual Table definition for channel handlers. See the documentation of aws_channel_handler() for more details.
 */
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

/**
 * An instance of a channel handler is owned by a channel. It's job is simple, it processes data from a queue that is passed
 * to it by the channel. As the handler is ready to pass the data to the next handler, it writes messages to its queue.
 * The handler does this in two directions. The first is the input direction, the second is the output direction.
 * Each handler has two queues, its input queue and an output queue. In addition, a channel handler can communicate to
 * the channel that it cannot process more data by setting its read or write flag to 0. When this happens, the channel
 * handler will be given the chance to process the data currently in its queue, but will not be passed more data until
 * it turns its flag back active. Finally, a channel handler need not pass input data to it's input queue.
 * For example, imagine a TLS channel handler. During the negotiation stage, no data should propagate to other handlers,
 * but it still needs to be processed as part of the TLS negotiation. The TLS engine will need to send output data
 * during this initial phase. In this case the data would pass directly from the handler's input read to its output queue.
 *
 * Implementing a channel handler uses standard C polymorphism:
 *
 * destroy() Inside this function you clean up any allocated resources, and finally free the (likely)
 * dynamically allocated memory to the object itself.
 *
 * process_input_messages() Here a queue containing the data you should read from is passed to you.
 * Read as many messages as you can and process them. When you have messages ready to be propagated to the next handler,
 * you queue them on input_queue. If you have messages that do not need to be passed as input to the next handler,
 * but needs to go in the write direction you can queue them on output_queue here as well.
 *
 * process_output_messages() Similar to process_input_messages(), you receive a queue with messages for the output direction,
 * process and queue them on output_queue.
 *
 * handle_channel_shutdown() Will be invoked when the channel is shutting down. At this point, flush any pending messages
 * or take handle the shutdown procedure for your handler e.g. TLS shutdown, or H2 GOAWAY etc...
 *
 * To implement a handler,
 * you need to declare a struct with an identical layout to struct aws_io_channel_handler, and fill in the vtable with
 * functions matching the signatures of each function in the vtable. You can certainly add more fields to your structure
 * as long as it is at the end of the struct aws_io_channel_handler layout.
 *
 * Keep in mind, that for a channel to be useful, it will have to eventually expose an API to users outside of the channel.
 * For instance, if the channel only decrypts data of TLS and then wants to expose that information directly to the user
 * for processing, the TLS handler could expose a callback called void(*on_data_read)(uint8_t *data, size_t len).
 * When the handler processes input data and has decrypted data available, it could invoke this callback.
 * Similarly, it could expose a function to the user called int write_data(uint8_t *data, size_t len).
 * This would cause the handler to encrypt the data and queue it up for write in the channel.
 *
 * To facilitate this ability, the channel passes a flag to each handler function notifying it that it is that
 * final handler in the chain and it should not attempt to send data to it's input_queue or read data from an output queue.
 * Instead it should exercise its user API.
 *
 * One very important point here. It is the handler's responsibility to do a thread check.
 * If the user invokes a function on a handler that is NOT in the channel's thread, the handler MUST go through the channel's
 * task scheduler before mutating any state. To facilitate this need, the channel exposes two functions:
 *
 * int8_t aws_channel_thread_check(struct aws_channel *channel);
 * int aws_channel_schedule_task(struct aws_channel *channel, struct aws_task *task, uint64_t run_at);
 *
 * aws_channel_thread_check() returns 1 if the caller is in the channel's thread. If so then it is safe to proceed.
 * If not, then you must move the instructions to the task scheduler.
 * aws_channel_schedule_task() Will run any task at the time specified by run_at.
 * The value of task is copied in order to save on memory allocations.
 */
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
/**
 * Initializes the state of the base portion of the channel handler. All channel handler implementations must call
 * this function after allocating the memory for their implementation.
 */
AWS_IO_API int aws_channel_handler_init_base(struct aws_channel_handler *channel_handler, struct aws_allocator *alloc);

/**
 * Cleans up the state of the base portion of the channel handler. All channel handler implementations must call this
 * function before deallocating the memory for their implementation.
 */
AWS_IO_API void aws_channel_handler_clean_up_base(struct aws_channel_handler *channel_handler);

/**
 * Invokes the destroy() fn on the vtable.
 */
AWS_IO_API void aws_channel_handler_destroy(struct aws_channel_handler *channel_handler);

/**
 * Invokes the process_input() fn on the vtable.
 */
AWS_IO_API int aws_channel_handler_process_input(struct aws_channel_handler *channel_handler,
                                struct aws_channel *channel, aws_message_queue *queue, int8_t is_end_of_chain);

/**
 * Invokes the process_output() fn on the vtable.
 */
AWS_IO_API int aws_channel_handler_process_output(struct aws_channel_handler *channel_handler,
            struct aws_channel *channel, aws_message_queue *queue);

/**
 * Invokes the handle_channel_shutdown() fn on the vtable.
 */
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

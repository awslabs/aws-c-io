/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/logging.h>
#include <aws/common/assert.h>
#include <aws/common/error.h>
#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/common/byte_buf.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/array_list.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/io.h>
#include <aws/io/socks5_channel_handler.h>
#include <aws/io/tls_channel_handler.h>
#include <inttypes.h>


/* Structure for passing both proxy options and original user data */
struct aws_http_proxy_user_data {
    struct aws_allocator *allocator;
    void *proxy_options;
    void *user_data;
};

/* Structure to store context for the channel-bootstrap adapter */
struct aws_socks5_adapter_context {
    struct aws_client_bootstrap *bootstrap;
    aws_client_bootstrap_on_channel_event_fn *original_callback;
    void *original_user_data;
};

static int s_socks5_bootstrap_begin_handshake(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    struct aws_channel *channel);

static int s_socks5_bootstrap_start_endpoint_resolution(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    const struct aws_socket_channel_bootstrap_options *channel_options);

static void s_socks5_bootstrap_resolution_success_task(
    struct aws_channel_task *task,
    void *arg,
    enum aws_task_status status);

static void s_socks5_bootstrap_resolution_failure_task(
    struct aws_channel_task *task,
    void *arg,
    enum aws_task_status status);

static void s_socks5_on_host_resolved(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data);

static const struct aws_socks5_system_vtable s_default_socks5_system_vtable = {
    .aws_client_bootstrap_new_socket_channel = aws_client_bootstrap_new_socket_channel,
};

static const struct aws_socks5_system_vtable *s_socks5_system_vtable = &s_default_socks5_system_vtable;

void aws_socks5_channel_handler_set_system_vtable(const struct aws_socks5_system_vtable *system_vtable) {
    if (system_vtable != NULL) {
        s_socks5_system_vtable = system_vtable;
    } else {
        s_socks5_system_vtable = &s_default_socks5_system_vtable;
    }
}

/**
 * State machine for the SOCKS5 channel handler
 * 
 * Valid state transitions:
 * INIT -> GREETING (when handshake starts)
 * GREETING -> AUTH (if authentication required)
 * GREETING -> CONNECT (if no authentication required)
 * AUTH -> CONNECT (after authentication completes)
 * CONNECT -> ESTABLISHED (when connection established)
 * ANY -> ERROR (on any error)
 *
 * These states align with but are distinct from the protocol states in aws_socks5_state.
 * This represents the channel handler's state specifically.
 */
enum aws_socks5_channel_state {
    AWS_SOCKS5_CHANNEL_STATE_INIT,              /* Initial state before handshake begins */
    AWS_SOCKS5_CHANNEL_STATE_GREETING,          /* Sending greeting and processing response */
    AWS_SOCKS5_CHANNEL_STATE_AUTH,              /* Performing authentication if required */
    AWS_SOCKS5_CHANNEL_STATE_CONNECT,           /* Sending connect request and processing response */
    AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED,       /* Connection established, ready for data transfer */
    AWS_SOCKS5_CHANNEL_STATE_ERROR              /* Error occurred, no further progress possible */
};

/**
 * Converts a SOCKS5 channel state to a readable string for logging purposes.
 * This improves log readability by providing human-readable state names.
 * 
 */
static inline const char *s_socks5_channel_state_to_string(enum aws_socks5_channel_state state) {
    switch (state) {
        case AWS_SOCKS5_CHANNEL_STATE_INIT:
            return "INIT";
        case AWS_SOCKS5_CHANNEL_STATE_GREETING:
            return "GREETING";
        case AWS_SOCKS5_CHANNEL_STATE_AUTH:
            return "AUTH";
        case AWS_SOCKS5_CHANNEL_STATE_CONNECT:
            return "CONNECT";
        case AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED:
            return "ESTABLISHED";
        case AWS_SOCKS5_CHANNEL_STATE_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

/**
 * Returns a human-readable name for SOCKS5 message types used in logging.
 * This aids in debugging by providing context about the type of message
 * being processed in the SOCKS5 protocol.
 */
static inline const char *s_get_socks5_message_type_name(int message_type) {
    switch (message_type) {
        case 0:
            return "INIT";
        case 1:
            return "GREETING";
        case 2:
            return "AUTH";
        case 3:
            return "CONNECT";
        default:
            return "UNKNOWN";
    }
}

struct aws_socks5_channel_handler {
    /* Base handler data */
    struct aws_channel_handler handler;
    struct aws_allocator *allocator;
    struct aws_channel_slot *slot; /* Current channel slot */
    
    /* Channel and connection state */
    enum aws_socks5_channel_state channel_state;
    int error_code;
    bool process_incoming_data;
    
    /* SOCKS5 protocol context and buffers */
    struct aws_socks5_context context;
    struct aws_byte_buf send_buffer; /* Buffer for outgoing SOCKS5 protocol messages */
    struct aws_byte_buf read_buffer; /* Buffer for accumulating incoming data */
    
    /* Callback management */
    aws_channel_on_setup_completed_fn *on_setup_completed;
    void *user_data;

    /* Timeout management */
    uint64_t connect_timeout_ns;
    struct aws_channel_task timeout_task;
    bool timeout_task_scheduled;
};

/**
 * Cancels any pending timeout task for a SOCKS5 handler.
 * 
 * This function safely cancels any scheduled timeout task to prevent it
 * from executing after it's no longer needed (such as when a connection
 * is successfully established or when shutting down).
 * 
 * @param handler The SOCKS5 channel handler
 */
static void s_cancel_timeout_task(struct aws_socks5_channel_handler *handler) {
    if (!handler) {
        return;
    }
    
    /* Only mark as not scheduled so the handler can check this when it runs */
    if (handler->timeout_task_scheduled) {
        handler->timeout_task_scheduled = false;
        
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: Marked SOCKS5 timeout task as canceled",
            (void *)handler);
    }
}

/**
 * Helper function for logging and handling state transitions in the SOCKS5 handler.
 * 
 * This function manages state transitions with proper logging and error handling.
 * It ensures that error codes are recorded when transitioning to an error state
 * and provides detailed logging about state changes for debugging.
 * 
 * @param handler The SOCKS5 channel handler
 * @param new_state The state to transition to
 * @param error_code Error code if transitioning due to an error, 0 otherwise
 */
static void s_transition_state(
    struct aws_socks5_channel_handler *handler,
    enum aws_socks5_channel_state new_state,
    int error_code) {
    
    if (!handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_transition_state called with NULL handler");
        return;
    }

    /* Store old state before modifying anything */
    enum aws_socks5_channel_state old_state = handler->channel_state;
    
    /* Validate state transition - certain transitions aren't allowed */
    if (old_state == AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED && 
        new_state != AWS_SOCKS5_CHANNEL_STATE_ERROR) {
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKS5,
            "id=%p: Invalid state transition attempted: %s -> %s (only ERROR state allowed from ESTABLISHED)",
            (void *)handler,
            s_socks5_channel_state_to_string(old_state),
            s_socks5_channel_state_to_string(new_state));
        return;
    }
    
    if (old_state == AWS_SOCKS5_CHANNEL_STATE_ERROR) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: State transition from ERROR state ignored: %s -> %s",
            (void *)handler,
            s_socks5_channel_state_to_string(old_state),
            s_socks5_channel_state_to_string(new_state));
        return;
    }
    
    /* Get state names for logging */
    const char *old_state_name = s_socks5_channel_state_to_string(old_state);
    const char *new_state_name = s_socks5_channel_state_to_string(new_state);
    
    /* Set new state */
    handler->channel_state = new_state;
    
    /* If transitioning to error state, record the error code */
    if (new_state == AWS_SOCKS5_CHANNEL_STATE_ERROR && error_code) {
        handler->error_code = error_code;
    }
    
    /* Log the state transition */
    if (old_state != new_state) {
        uint64_t now = 0;
        if (handler->slot && handler->slot->channel) {
            /* Get current time for performance tracking if possible */
            aws_channel_current_clock_time(handler->slot->channel, &now);
        }
        
        if (new_state == AWS_SOCKS5_CHANNEL_STATE_ERROR) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: State transition: %s -> %s with error %d (%s) at %" PRIu64 "ns",
                (void *)handler,
                old_state_name,
                new_state_name,
                error_code,
                aws_error_str(error_code),
                now);
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKS5,
                "id=%p: State transition: %s -> %s at %" PRIu64 "ns",
                (void *)handler,
                old_state_name,
                new_state_name,
                now);
            
            /* Add additional context based on the new state */
            if (new_state == AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED) {
                AWS_LOGF_INFO(
                    AWS_LS_IO_SOCKS5,
                    "id=%p: SOCKS5 connection established successfully",
                    (void *)handler);
                
                /* Cancel any timeout task when established */
                s_cancel_timeout_task(handler);
                
            } else if (new_state == AWS_SOCKS5_CHANNEL_STATE_GREETING) {
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKS5,
                    "id=%p: Beginning SOCKS5 handshake",
                    (void *)handler);
            }
        }
    }
}

/**
 * Helper function to ensure a buffer has at least the specified capacity.
 * If the buffer is NULL or not properly initialized, it initializes it.
 * If the buffer doesn't have enough capacity, it reallocates.
 * 
 * @return AWS_OP_SUCCESS on success, AWS_OP_ERR on failure
 */
static int s_ensure_buffer_capacity(
    struct aws_byte_buf *buffer,
    struct aws_allocator *allocator,
    size_t needed_capacity) {
    
    /* Default minimum capacity for new buffers */
    const size_t DEFAULT_MIN_CAPACITY = 256;
    
    if (!buffer || !allocator) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* If buffer is not initialized or doesn't have enough capacity */
    if (buffer->buffer == NULL || buffer->capacity == 0 || buffer->capacity < needed_capacity) {
        /* Clean up existing buffer if any */
        if (buffer->buffer != NULL) {
            aws_byte_buf_clean_up(buffer);
        }
        
        /* Calculate new capacity - at least double the needed capacity or DEFAULT_MIN_CAPACITY */
        size_t new_capacity = needed_capacity * 2;
        if (new_capacity < DEFAULT_MIN_CAPACITY) {
            new_capacity = DEFAULT_MIN_CAPACITY;
        }
        
        /* Initialize with new capacity */
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "Initializing buffer with capacity %zu (needed %zu)",
            new_capacity,
            needed_capacity);
        
        return aws_byte_buf_init(buffer, allocator, new_capacity);
    }
    
    return AWS_OP_SUCCESS;
}

/**
 * Helper function to reset a buffer and ensure it has enough capacity.
 * Useful before writing new data to a buffer.
 * 
 * @return AWS_OP_SUCCESS on success, AWS_OP_ERR on failure
 */
static int s_reset_and_ensure_buffer(
    struct aws_byte_buf *buffer, 
    struct aws_allocator *allocator,
    size_t needed_capacity) {
    
    if (!buffer || !allocator) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Reset the buffer but keep its memory */
    aws_byte_buf_reset(buffer, false);
    
    /* Ensure it has enough capacity */
    return s_ensure_buffer_capacity(buffer, allocator, needed_capacity);
}

/**
 * Cleanup and destroy function for the SOCKS5 channel handler.
 * 
 * This function is responsible for properly cleaning up and releasing all resources
 * associated with a SOCKS5 channel handler, including:
 * - SOCKS5 protocol context (credentials, target info, etc.)
 * - Internal buffers used for protocol messages
 * - The handler structure itself
 * 
 * It performs thorough null-checking to handle partially initialized handlers safely.
 * Any sensitive data (like credentials) is zeroed out before memory is released.
 */
static void s_socks5_handler_destroy(struct aws_channel_handler *handler) {
    AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: Destroying SOCKS5 channel handler", (void *)handler);

    if (handler == NULL) {
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=static: s_socks5_handler_destroy - NULL handler, nothing to do");
        return;
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    if (socks5_handler == NULL) {
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=%p: s_socks5_handler_destroy - NULL implementation", (void *)handler);
        return;
    }
    
    /* Save allocator before cleaning up (we'll need it for final memory release) */
    struct aws_allocator *allocator = socks5_handler->allocator;
    
    if (!allocator) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=%p: s_socks5_handler_destroy - NULL allocator, memory leak likely", (void *)handler);
        return;
    }
    
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=%p: Cleaning up SOCKS5 context and buffers", (void *)handler);
    
    /* Clean up the SOCKS5 context */
    aws_socks5_context_clean_up(&socks5_handler->context);
    
    /* Clean up buffers (safely handles non-initialized buffers) */
    if (socks5_handler->send_buffer.buffer != NULL) {
        aws_byte_buf_clean_up(&socks5_handler->send_buffer);
    }
    
    if (socks5_handler->read_buffer.buffer != NULL) {
        aws_byte_buf_clean_up(&socks5_handler->read_buffer);
    }
    
    /* Clear any sensitive data before releasing memory */
    AWS_ZERO_STRUCT(*socks5_handler);
    
    /* Release the handler memory */
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=%p: Releasing SOCKS5 handler memory", (void *)handler);
    aws_mem_release(allocator, socks5_handler);
}

/* Forward declarations of helper functions */
static void s_process_read_message(
    struct aws_channel_handler *handler, 
    struct aws_channel_slot *slot,
    struct aws_io_message *message);

static void s_handle_timeout(struct aws_channel_task *task, void *arg, enum aws_task_status status);

static void s_forward_pending_data_task(struct aws_channel_task *task, void *arg, enum aws_task_status status);


/**
 * Safely invokes the setup callback, ensuring it's only called once.
 * 
 * Callbacks are invoked safely by:
 * 1. Storing callback references locally before nulling them
 * 2. Performing single-operation checks to prevent race conditions
 * 3. Using proper error handling for all edge cases
 * 
 * @param handler The SOCKS5 channel handler
 * @param error_code Error code to pass to the callback (AWS_OP_SUCCESS for success)
 */
static void s_invoke_setup_callback_safely(
    struct aws_socks5_channel_handler *handler,
    int error_code) {
    
    /* Safety checks */
    if (!handler) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: s_invoke_setup_callback_safely - NULL handler");
        return;
    }
    
    /* Store callback and data locally before clearing */
    aws_channel_on_setup_completed_fn *callback = handler->on_setup_completed;
    void *user_data = handler->user_data;
    
    /* Clear callback first to prevent double-invocation in any subsequent calls */
    handler->on_setup_completed = NULL;
    
    /* Only proceed if we had a valid callback */
    if (!callback) {
        AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: No callback to invoke (already called or never set)", (void *)handler);
        return;
    }
    
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Invoking setup callback with error_code=%d (%s)",
        (void *)handler,
        error_code,
        aws_error_str(error_code));
    
    /* Determine channel to use (might be NULL if handler isn't properly connected) */
    struct aws_channel *channel = NULL;
    
    if (handler->slot && handler->slot->channel) {
        channel = handler->slot->channel;
    } else if (error_code == AWS_OP_SUCCESS) {
        /* If we're reporting success but don't have a channel, that's an error */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Attempted to signal success without valid channel",
            (void *)handler);
        error_code = AWS_ERROR_INVALID_STATE;
    }
    
    /* Invoke the stored callback with appropriate parameters */
    callback(channel, error_code, user_data);
}

/**
 * Processes incoming messages from the channel.
 * 
 * This function handles all incoming data based on the current state of the SOCKS5 handler:
 * 1. In ESTABLISHED state: forwards messages upstream (transparent proxy mode)
 * 2. In ERROR state: drops messages and logs errors
 * 3. During handshake states: processes protocol messages for the SOCKS5 handshake
 * 
 * The function is a critical part of the channel's read path, determining whether
 * messages are processed for SOCKS5 protocol handling or forwarded to the application.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param message The incoming message to process
 * @return AWS_OP_SUCCESS on successful handling (even if message is consumed)
 *         AWS_OP_ERR on error (with aws_last_error set)
 */
static int s_socks5_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    
    /* Validate input parameters */
    if (!handler || !slot || !message) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_socks5_handler_process_read_message - Invalid arguments: handler=%p, slot=%p, message=%p",
            (void *)handler, 
            (void *)slot, 
            (void *)message);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    if (!socks5_handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_socks5_handler_process_read_message - NULL implementation",
            (void *)handler);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* If we're in established state, pass the message up the channel */
    if (socks5_handler->channel_state == AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Connection established, forwarding message of size %zu",
            (void *)handler,
            message->message_data.len);
        
        /* Forward the message to the next handler in the read direction */
        int result = aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_READ);
        if (result != AWS_OP_SUCCESS) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to forward message upstream, error=%d (%s)",
                (void *)handler,
                error_code,
                aws_error_str(error_code));
        }
        return result;
    }
    
    /* If we're in error state, drop the message */
    if (socks5_handler->channel_state == AWS_SOCKS5_CHANNEL_STATE_ERROR) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: In error state, dropping incoming message of size %zu",
            (void *)handler,
            message->message_data.len);
        
        /* Release the message since we're not forwarding it */
        aws_mem_release(message->allocator, message);
        return AWS_OP_SUCCESS;
    }
    
    /* We're in handshake state, check if we should process the message */
    if (socks5_handler->process_incoming_data) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Processing incoming data for SOCKS5 handshake in state %d",
            (void *)handler,
            socks5_handler->channel_state);
            
        /* Process the message using our internal handler */
        s_process_read_message(handler, slot, message);
        return AWS_OP_SUCCESS;
    }
    
    /* We're not processing data (unusual case), log and drop the message */
    AWS_LOGF_WARN(
        AWS_LS_IO_SOCKS5,
        "id=%p: Not processing incoming data (flag not set) in SOCKS5 state %d, dropping message of size %zu",
        (void *)handler,
        socks5_handler->channel_state,
        message->message_data.len);
    
    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
}

/**
 * Processes outgoing messages to the channel.
 * 
 * This function handles all outgoing data based on the current state of the SOCKS5 handler:
 * 1. In ESTABLISHED state: forwards messages downstream (transparent proxy mode)
 * 2. During handshake or ERROR states: blocks application data from being sent
 *    until the SOCKS5 connection is fully established
 * 
 * This ensures that application data isn't sent over the connection until the
 * SOCKS5 handshake is complete and the tunnel is established.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param message The outgoing message to process
 * @return AWS_OP_SUCCESS on successful handling (even if message is dropped)
 *         AWS_OP_ERR on error (with aws_last_error set)
 */
static int s_socks5_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    
    /* Validate input parameters */
    if (!handler || !slot || !message) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_socks5_handler_process_write_message - Invalid arguments: handler=%p, slot=%p, message=%p",
            (void *)handler, 
            (void *)slot, 
            (void *)message);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    if (!socks5_handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_socks5_handler_process_write_message - NULL implementation",
            (void *)handler);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* If we're in established state, pass the message down the channel */
    if (socks5_handler->channel_state == AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Connection established, forwarding outgoing message of size %zu",
            (void *)handler,
            message->message_data.len);
            
        /* Forward the message to the next handler in the write direction */
        int result = aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE);
        if (result != AWS_OP_SUCCESS) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to forward outgoing message, error=%d (%s)",
                (void *)handler,
                error_code,
                aws_error_str(error_code));
        }
        return result;
    }
    
    /* If we're in error state or still in handshake, drop application data */
    AWS_LOGF_WARN(
        AWS_LS_IO_SOCKS5,
        "id=%p: Not in established state (current state: %d), dropping outgoing message of size %zu",
        (void *)handler,
        socks5_handler->channel_state,
        message->message_data.len);
    
    /* Release the message since we're not forwarding it */
    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
}

/**
 * Handles window updates for flow control in the SOCKS5 channel handler.
 * 
 * When the handler receives a window update (meaning more data can be received),
 * it propagates this update to the adjacent handler to maintain proper flow control
 * throughout the channel. This function is part of the AWS CRT channel's 
 * backpressure mechanism.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param window_update The number of bytes to increase the window by
 * @return AWS_OP_SUCCESS on successful handling
 *         AWS_OP_ERR on error (with aws_last_error set)
 */
static int s_socks5_handler_initial_window_update(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t window_update) {
    
    /* Validate input parameters */
    if (!handler || !slot) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_socks5_handler_initial_window_update - Invalid arguments: handler=%p, slot=%p",
            (void *)handler, 
            (void *)slot);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Log the window update */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Window update of %zu bytes",
        (void *)handler,
        window_update);
    
    /* Propagate the window update to the adjacent handler */
    if (slot->adj_right) {
        aws_channel_slot_increment_read_window(slot->adj_right, window_update);
    } else {
        /* Not having an adjacent slot is normal during setup/teardown */
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: No adjacent slot for window update of %zu bytes",
            (void *)handler,
            window_update);
    }
    
    return AWS_OP_SUCCESS;
}

/**
 * Handles channel shutdown events for the SOCKS5 channel handler.
 * 
 * This function is called during channel shutdown to:
 * 1. Cancel any pending timeouts
 * 2. Record error information if shutdown occurs during handshake
 * 3. Safely invoke any pending callbacks
 * 4. Propagate the shutdown signal to adjacent handlers
 * 
 * Proper handling of shutdown is critical for clean resource cleanup and
 * appropriate error propagation throughout the channel stack.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param dir The direction of shutdown (read or write)
 * @param error_code The error that caused shutdown, or 0 for normal shutdown
 * @param free_scarce_resources_immediately Whether to free resources immediately
 * @return AWS_OP_SUCCESS on successful shutdown handling
 *         AWS_OP_ERR on error (with aws_last_error set)
 */
static int s_socks5_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {
    
    /* Validate input parameters */
    if (!handler || !slot) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_socks5_handler_shutdown - Invalid arguments: handler=%p, slot=%p",
            (void *)handler, 
            (void *)slot);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    if (!socks5_handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_socks5_handler_shutdown - NULL implementation",
            (void *)handler);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Log shutdown information */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Shutting down SOCKS5 handler, direction=%s, error_code=%d, free_resources=%d",
        (void *)handler,
        dir == AWS_CHANNEL_DIR_READ ? "READ" : "WRITE",
        error_code,
        free_scarce_resources_immediately);
    
    /* For read direction with no error, use socket closed as the reason */
    if (dir == AWS_CHANNEL_DIR_READ && !error_code) {
        error_code = AWS_IO_SOCKET_CLOSED;
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: Read direction shutdown with no error, using AWS_IO_SOCKET_CLOSED",
            (void *)handler);
    }
    
    /* Properly cancel any pending timeout task */
    s_cancel_timeout_task(socks5_handler);
    
    /* Handle shutdown during handshake */
    if (socks5_handler->channel_state != AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED && 
        socks5_handler->channel_state != AWS_SOCKS5_CHANNEL_STATE_ERROR &&
        error_code) {
        /* If we're not established yet, transition to error state */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Shutdown during handshake (state %d), error_code=%d (%s)",
            (void *)handler,
            socks5_handler->channel_state,
            error_code,
            aws_error_str(error_code));
            
        /* Record the error and update state */
        socks5_handler->error_code = error_code;
        s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_ERROR, error_code);
        
        /* If we have a pending callback, invoke it with the error */
        if (socks5_handler->on_setup_completed != NULL) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKS5,
                "id=%p: Invoking pending callback with error during shutdown",
                (void *)handler);
            s_invoke_setup_callback_safely(socks5_handler, error_code);
        }
    }
    
    /* Propagate shutdown to adjacent handlers */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Propagating shutdown to adjacent handlers",
        (void *)handler);
        
    aws_channel_slot_on_handler_shutdown_complete(
        slot, dir, error_code, free_scarce_resources_immediately);
    
    return AWS_OP_SUCCESS;
}

/**
 * Returns the initial window size for the SOCKS5 channel handler.
 * 
 * This function delegates to the next handler in the chain to ensure
 * consistent window sizing throughout the channel. If there's no
 * next handler available, it returns a sensible default value.
 * 
 * The window size is critical for flow control in the channel architecture,
 * controlling how much data a handler is willing to receive before needing
 * acknowledgment.
 */
static size_t s_socks5_handler_get_initial_window_size(struct aws_channel_handler *handler) {
    /* Default window size if we can't delegate */
    const size_t DEFAULT_WINDOW_SIZE = 16 * 1024; /* 16 KB is a reasonable default */
    
    if (!handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_socks5_handler_get_initial_window_size - NULL handler");
        return DEFAULT_WINDOW_SIZE;
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    /* Safety check for the handler implementation */
    if (!socks5_handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_socks5_handler_get_initial_window_size - NULL implementation", 
            (void *)handler);
        return DEFAULT_WINDOW_SIZE;
    }
    
    /* Safety check for the slot */
    if (!socks5_handler->slot) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_socks5_handler_get_initial_window_size - No slot assigned yet", 
            (void *)handler);
        return DEFAULT_WINDOW_SIZE;
    }
    
    struct aws_channel_slot *adj_slot = socks5_handler->slot->adj_right;
    
    /* Check for adjacent slot and handler */
    if (adj_slot && adj_slot->handler && adj_slot->handler->vtable && 
        adj_slot->handler->vtable->initial_window_size) {
        
        /* Delegate to the next handler */
        size_t next_window_size = adj_slot->handler->vtable->initial_window_size(adj_slot->handler);
        
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Using adjacent handler's window size: %zu", 
            (void *)handler, 
            next_window_size);
            
        return next_window_size;
    }
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: No adjacent handler with window size, using default: %zu", 
        (void *)handler, 
        DEFAULT_WINDOW_SIZE);
    
    /* Return default window size if we can't delegate */
    return DEFAULT_WINDOW_SIZE;
}

/**
 * Returns the message overhead that the SOCKS5 handler adds to each message.
 * 
 * Once the SOCKS5 handshake is complete, the handler becomes a simple pass-through
 * that doesn't add any additional overhead to messages. Therefore, this function
 * returns 0 to indicate no additional memory allocation is needed for messages
 * passing through this handler.
 * 
 * During the handshake phase, the handler processes protocol-specific messages
 * internally and doesn't add overhead to application messages.
 */
static size_t s_socks5_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    /* Return 0 since SOCKS5 doesn't add any overhead to messages passing through */
    return 0;
}

static struct aws_channel_handler_vtable s_socks5_handler_vtable = {
    .destroy = s_socks5_handler_destroy,
    .process_read_message = s_socks5_handler_process_read_message,
    .process_write_message = s_socks5_handler_process_write_message,
    .increment_read_window = s_socks5_handler_initial_window_update,
    .shutdown = s_socks5_handler_shutdown,
    .initial_window_size = s_socks5_handler_get_initial_window_size,
    .message_overhead = s_socks5_handler_message_overhead,
};

/* Send a SOCKS5 protocol message down the channel */
static int s_send_socks5_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buffer) {
    
    if (!handler || !slot || !buffer || buffer->len == 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    if (!slot->channel || !slot->adj_left) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    struct aws_io_message *message = aws_channel_acquire_message_from_pool(
        slot->channel,
        AWS_IO_MESSAGE_APPLICATION_DATA,
        buffer->len);    if (!message) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to acquire message from pool, size=%zu",
            (void *)handler,
            buffer->len);
        return AWS_OP_ERR;
    }
    
    /* Copy the buffer content into the message */
    if (!aws_byte_buf_write(
            &message->message_data, buffer->buffer, buffer->len)) {
        aws_mem_release(message->allocator, message);
        return AWS_OP_ERR;
    }
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Sending SOCKS5 message, size=%zu",
        (void *)handler,
        message->message_data.len);

    
    /* Send the message down the channel */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=static: s_send_socks5_message - Sending message of size %zu down channel in slot %p", 
        message->message_data.len, (void *)slot);
    if (aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(message->allocator, message);
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_send_socks5_message - Failed to send message down channel");
        return AWS_OP_ERR;
    }
    
    return AWS_OP_SUCCESS;
}

/* Invoke the user's setup completed callback */
/**
 * Helper function to transition to error state and invoke callback
 * 
 * This centralizes error handling for the SOCKS5 handler by:
 * 1. Transitioning to error state with proper logging
 * 2. Recording the error code
 * 3. Invoking the setup callback with the error
 *
 */
static void s_transition_to_error(
    struct aws_socks5_channel_handler *handler,
    int error_code) {
    
    if (!handler) {
        return;
    }
    
    /* Update the state */
    s_transition_state(handler, AWS_SOCKS5_CHANNEL_STATE_ERROR, error_code);
    
    /* Invoke the callback with the error */
    s_invoke_setup_callback_safely(handler, error_code);
}

/* Start the connection timeout timer */
/**
 * Schedules a timeout task for the SOCKS5 handshake.
 * 
 * This ensures that the SOCKS5 handshake doesn't hang indefinitely
 * if the proxy server doesn't respond or if there are network issues.
 * The timeout is based on the connect_timeout_ns value specified in
 * the handler's configuration.
 * 
 * @param handler The SOCKS5 channel handler
 */
static void s_schedule_timeout(struct aws_socks5_channel_handler *handler) {
    /* Validate handler and channel availability */
    if (!handler) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, 
            "id=static: s_schedule_timeout called with NULL handler");
        return;
    }
    
    if (!handler->slot || !handler->slot->channel) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: Cannot schedule timeout - missing slot or channel",
            (void *)handler);
        return;
    }
    
    /* Skip if timeout disabled or already scheduled */
    if (handler->connect_timeout_ns == 0) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 connection timeout disabled (connect_timeout_ns=0)",
            (void *)handler);
        return;
    }
    
    if (handler->timeout_task_scheduled) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 timeout task already scheduled",
            (void *)handler);
        return;
    }
    
    /* Get current time for scheduling */
    uint64_t now = 0;
    if (aws_channel_current_clock_time(handler->slot->channel, &now)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to get current time for timeout scheduling",
            (void *)handler);
        return;
    }
    
    /* Calculate absolute timeout time */
    uint64_t timeout_time = now + handler->connect_timeout_ns;
    
    /* Log timeout details in milliseconds for readability */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Scheduling SOCKS5 timeout for %" PRIu64 " ms from now (current state: %s)",
        (void *)handler,
        handler->connect_timeout_ns / 1000000, /* Convert ns to ms for more readable logs */
        s_socks5_channel_state_to_string(handler->channel_state));
    
    /* Initialize and schedule the timeout task */
    aws_channel_task_init(
        &handler->timeout_task,
        s_handle_timeout,
        handler,
        "socks5_channel_connect_timeout");
    
    aws_channel_schedule_task_future(
        handler->slot->channel,
        &handler->timeout_task,
        timeout_time);
    
    handler->timeout_task_scheduled = true;
    
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 timeout task scheduled for absolute time %" PRIu64,
        (void *)handler,
        timeout_time);
}

/**
 * Task function for safely forwarding data after the SOCKS5 handshake completes.
 * 
 * This is used to ensure that application data received alongside the final SOCKS5
 * response is properly forwarded to the application after all handlers have been 
 * properly installed in the channel.
 * 
 * @param task The channel task
 * @param arg Context containing the slot and message to forward and allocator
 * @param status Task status (cancelled or running)
 */
static void s_forward_pending_data_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    /* Check if task was cancelled */
    if (status == AWS_TASK_STATUS_CANCELED) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=static: s_forward_pending_data_task - Task was cancelled");
        return;
    }
    
    /* Check for valid context */
    if (!arg) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_forward_pending_data_task - NULL context");
        return;
    }
    
    /* Extract context */
    struct {
        struct aws_channel_slot *slot;
        struct aws_io_message *message;
        struct aws_allocator *allocator;
    } *forward_ctx = arg;
    
    /* Free the task immediately using the allocator from our context */
    struct aws_allocator *allocator = forward_ctx->allocator;
    if (task && allocator) {
        aws_mem_release(allocator, task);
    }
    
    /* Ensure we have valid slot and message */
    if (!forward_ctx->slot || !forward_ctx->message) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_forward_pending_data_task - Invalid slot or message");
        
        /* Free the context using the allocator we captured */
        if (allocator) {
            aws_mem_release(allocator, forward_ctx);
        }
        return;
    }
    
    /* Extract local copies for safety */
    struct aws_channel_slot *slot = forward_ctx->slot;
    struct aws_io_message *message = forward_ctx->message;
    
    /* Ensure channel is still valid */
    if (!slot->channel) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_forward_pending_data_task - Channel no longer valid");
            
        /* Clean up the message and context */
        aws_mem_release(message->allocator, message);
        if (allocator) {
            aws_mem_release(allocator, forward_ctx);
        }
        return;
    }
    
    /* Forward the message up the channel */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Forwarding %zu bytes of application data after SOCKS5 handshake",
        (void *)slot,
        message->message_data.len);
        
    if (aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_READ)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to forward pending data, error=%d (%s)",
            (void *)slot,
            error_code,
            aws_error_str(error_code));
            
        /* Clean up the message if send failed */
        aws_mem_release(message->allocator, message);
    }
    
    /* Clean up our context */
    if (allocator) {
        aws_mem_release(allocator, forward_ctx);
    }
}

/**
 * Handles the SOCKS5 connection timeout event.
 * 
 * This function is called when the timeout task executes, indicating that
 * the SOCKS5 handshake has taken too long. It fails the connection with
 * a timeout error and invokes the setup callback to notify higher layers.
 * 
 * This implementation includes better thread safety with explicit state checks
 * to ensure the timeout isn't processed if it was cancelled or the state changed.
 * 
 * @param task The timeout task
 * @param arg Handler pointer passed as context (cast to aws_socks5_channel_handler)
 * @param status The task status (may be cancelled)
 */
static void s_handle_timeout(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    
    /* Check if task was cancelled or has invalid arg */
    if (status == AWS_TASK_STATUS_CANCELED) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=static: s_handle_timeout - Task was cancelled");
        return;
    }
    
    if (!arg) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: s_handle_timeout - NULL handler argument");
        return;
    }
    
    struct aws_socks5_channel_handler *handler = arg;
    
    /* Critical atomic check - don't run if task was cancelled via flag */
    if (!handler->timeout_task_scheduled) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Timeout task cancelled before execution",
            (void *)handler);
        return;
    }
    
    /* Clear the scheduled flag to prevent double execution */
    handler->timeout_task_scheduled = false;
    
    /* Log the timeout execution with handler state */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 timeout handler executed in state %s",
        (void *)handler,
        s_socks5_channel_state_to_string(handler->channel_state));
    
    /* Check if timeout is still relevant */
    if (handler->channel_state == AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 timeout ignored - connection already established",
            (void *)handler);
        return;
    }
    
    if (handler->channel_state == AWS_SOCKS5_CHANNEL_STATE_ERROR) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 timeout ignored - already in error state with code %d (%s)",
            (void *)handler,
            handler->error_code,
            aws_error_str(handler->error_code));
        return;
    }
    
    /* Connection timed out - log details of the current state */
    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 connection timed out after %" PRIu64 " ms in state %s",
        (void *)handler,
        handler->connect_timeout_ns / 1000000, /* Convert to ms for readable logs */
        s_socks5_channel_state_to_string(handler->channel_state));
    
    /* Use transition_state for consistent state management and logging */
    s_transition_state(handler, AWS_SOCKS5_CHANNEL_STATE_ERROR, AWS_IO_SOCKET_TIMEOUT);
    
    /* Invoke the callback with timeout error */
    s_invoke_setup_callback_safely(handler, AWS_IO_SOCKET_TIMEOUT);
}

/* Initialize the SOCKS5 handshake */
static int s_start_socks5_handshake(struct aws_channel_handler *handler, struct aws_channel_slot *slot) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=static: s_start_socks5_handshake called with handler %p, slot %p", 
        (void*)handler, (void*)slot);
           
    if (!handler) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: s_start_socks5_handshake - NULL handler!");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    if (!slot) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: s_start_socks5_handshake - NULL slot! (This is a programming error)");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    if (!slot->channel) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: s_start_socks5_handshake - Slot has no channel! (This is a programming error)");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    if (!socks5_handler) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: s_start_socks5_handshake - Handler has no impl! (This is a programming error)");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Store the slot for future reference */
    handler->slot = slot;
    socks5_handler->slot = slot;
    
    /* Validate target host before proceeding */
    struct aws_string *ctx_target_host = socks5_handler->context.endpoint_host;


    if (ctx_target_host == NULL) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=%p: Cannot start handshake - SOCKS5 target host buffer is NULL!", (void *)handler);

        int error_code = AWS_ERROR_INVALID_STATE;
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = error_code;
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        return aws_raise_error(error_code);
    }

    if (ctx_target_host->len == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=%p: Cannot start handshake - SOCKS5 target host length is 0!", (void *)handler);

        int error_code = AWS_ERROR_INVALID_STATE;
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = error_code;
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        return aws_raise_error(error_code);
    }
    
    /* Debug target host info */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 target host: '%.*s', port: %d",
        (void *)handler,
        (int)ctx_target_host->len,
        (const char *)ctx_target_host->bytes,
        socks5_handler->context.endpoint_port);
    
    /* Clear the buffer for sending the greeting */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Resetting send buffer before greeting (buffer=%p, capacity=%zu, len=%zu)",
        (void *)handler,
        (void*)socks5_handler->send_buffer.buffer, 
        socks5_handler->send_buffer.capacity, 
        socks5_handler->send_buffer.len);
    aws_byte_buf_reset(&socks5_handler->send_buffer, false);
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: After reset: send buffer state (buffer=%p, capacity=%zu, len=%zu)",
        (void *)handler,
        (void*)socks5_handler->send_buffer.buffer, 
        socks5_handler->send_buffer.capacity, 
        socks5_handler->send_buffer.len);
    
    /* Start the timeout timer */
    s_schedule_timeout(socks5_handler);
    
    /* Start processing incoming data */
    socks5_handler->process_incoming_data = true;
    
    /* Start with greeting state */
    AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: Starting handshake by transitioning to GREETING state", (void *)handler);
    s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_GREETING, 0);
    
    /* Write SOCKS5 greeting message */
    if (aws_socks5_write_greeting(&socks5_handler->context, &socks5_handler->send_buffer)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to write SOCKS5 greeting, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        s_transition_to_error(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    /* Debug the greeting bytes */

    /* Send the greeting message */
    if (s_send_socks5_message(handler, slot, &socks5_handler->send_buffer)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to send SOCKS5 greeting, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));

        s_transition_to_error(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    AWS_LOGF_INFO(AWS_LS_IO_SOCKS5, "id=%p: Started SOCKS5 handshake", (void *)handler);
    return AWS_OP_SUCCESS;
}

/**
 * Processes the SOCKS5 greeting response from the proxy server.
 * 
 * This function handles the server's response to our initial greeting,
 * which includes the authentication method selected by the server.
 * Based on this response, we either proceed to authentication or
 * directly to the connect phase.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param data Cursor pointing to the response data
 * @return AWS_OP_SUCCESS if processing succeeded, AWS_OP_ERR otherwise
 */
static int s_process_greeting_response(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_cursor *data) {
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    /* Log greeting response data for debugging (limited bytes for security) */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Processing SOCKS5 greeting response of size %zu bytes",
        (void *)handler,
        data->len);
    
    /* Process the greeting response */
    uint64_t start_time = 0;
    if (socks5_handler->slot && socks5_handler->slot->channel) {
        aws_channel_current_clock_time(socks5_handler->slot->channel, &start_time);
    }
    
    if (aws_socks5_read_greeting_response(&socks5_handler->context, data)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to process SOCKS5 greeting response, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        s_transition_to_error(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    /* Log success and selected authentication method */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 greeting response processed successfully, selected auth method: %d",
        (void *)handler,
        socks5_handler->context.selected_auth);
        
    uint64_t end_time = 0;
    if (socks5_handler->slot && socks5_handler->slot->channel) {
        aws_channel_current_clock_time(socks5_handler->slot->channel, &end_time);
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Greeting response processing took %" PRIu64 "ns",
            (void *)handler,
            end_time - start_time);
    }
    
    /* Reset and ensure buffer capacity for next message */
    if (s_reset_and_ensure_buffer(&socks5_handler->send_buffer, socks5_handler->allocator, 256)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to reset send buffer, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        s_transition_to_error(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    /* Check if authentication is needed */
    if (socks5_handler->context.selected_auth == AWS_SOCKS5_AUTH_NONE) {
        /* No auth needed, proceed to connect phase */
        s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_CONNECT, 0);
        
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: No authentication needed, proceeding to connect phase",
            (void *)handler);
            
        /* Send connect request */               
        if (aws_socks5_write_connect_request(&socks5_handler->context, &socks5_handler->send_buffer)) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to write SOCKS5 connect request, error=%d (%s)",
                (void *)handler,
                error_code,
                aws_error_str(error_code));
                
            s_transition_to_error(socks5_handler, error_code);
            return AWS_OP_ERR;
        }
                
        /* Send the connect request message */
        if (s_send_socks5_message(handler, slot, &socks5_handler->send_buffer)) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to send SOCKS5 connect request, error=%d (%s)",
                (void *)handler,
                error_code,
                aws_error_str(error_code));
            
            s_transition_to_error(socks5_handler, error_code);
            return AWS_OP_ERR;
        }
    } else {
        /* Authentication needed */
        s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_AUTH, 0);
        
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: Authentication required, sending auth request",
            (void *)handler);
            
        /* Prepare auth request */
        if (aws_socks5_write_auth_request(&socks5_handler->context, &socks5_handler->send_buffer)) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to write SOCKS5 auth request, error=%d (%s)",
                (void *)handler,
                error_code,
                aws_error_str(error_code));
            
            socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
            socks5_handler->error_code = error_code;
            s_invoke_setup_callback_safely(socks5_handler, error_code);
            return AWS_OP_ERR;
        }
        
        /* Send the auth request message */
        if (s_send_socks5_message(handler, slot, &socks5_handler->send_buffer)) {
            int error_code = aws_last_error();
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to send SOCKS5 auth request, error=%d (%s)",
                (void *)handler,
                error_code,
                aws_error_str(error_code));
            
            s_transition_to_error(socks5_handler, error_code);
            return AWS_OP_ERR;
        }
    }
    
    return AWS_OP_SUCCESS;
}

/**
 * Processes the SOCKS5 authentication response from the proxy server.
 * 
 * After sending authentication credentials to the proxy server, this function
 * handles the server's response. If authentication succeeds, we proceed to
 * the connect phase to establish the connection to the target server.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param data Cursor pointing to the response data
 * @return AWS_OP_SUCCESS if processing succeeded, AWS_OP_ERR otherwise
 */
static int s_process_auth_response(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_cursor *data) {
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    /* Log authentication response data (limited bytes for security) */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Processing SOCKS5 authentication response of size %zu bytes",
        (void *)handler,
        data->len);
    
    /* Process the authentication response */
    uint64_t start_time = 0;
    if (socks5_handler->slot && socks5_handler->slot->channel) {
        aws_channel_current_clock_time(socks5_handler->slot->channel, &start_time);
    }
    
    if (aws_socks5_read_auth_response(&socks5_handler->context, data)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 authentication failed, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        /* Use transition_state for consistency and better logging */
        s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_ERROR, error_code);
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    /* Log successful authentication */
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 authentication successful",
        (void *)handler);
        
    uint64_t end_time = 0;
    if (socks5_handler->slot && socks5_handler->slot->channel) {
        aws_channel_current_clock_time(socks5_handler->slot->channel, &end_time);
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKS5,
            "id=%p: Auth response processing took %" PRIu64 "ns",
            (void *)handler,
            end_time - start_time);
    }
    
    /* Clear the buffer for connect request */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Resetting send buffer after auth response (buffer=%p, capacity=%zu, len=%zu)",
        (void *)handler,
        (void*)socks5_handler->send_buffer.buffer, 
        socks5_handler->send_buffer.capacity, 
        socks5_handler->send_buffer.len);
    aws_byte_buf_reset(&socks5_handler->send_buffer, false);
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: After reset: send buffer state (buffer=%p, capacity=%zu, len=%zu)",
        (void *)handler,
        (void*)socks5_handler->send_buffer.buffer, 
        socks5_handler->send_buffer.capacity, 
        socks5_handler->send_buffer.len);
    
    /* Authentication successful, proceed to connect phase */
    s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_CONNECT, 0);
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Authentication successful, proceeding to connect phase",
        (void *)handler);
        
    /* Send connect request */
    if (aws_socks5_write_connect_request(&socks5_handler->context, &socks5_handler->send_buffer)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to write SOCKS5 connect request, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = error_code;
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    /* Send the connect request message */
    if (s_send_socks5_message(handler, slot, &socks5_handler->send_buffer)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to send SOCKS5 connect request, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = error_code;
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    return AWS_OP_SUCCESS;
}

/**
 * Processes the SOCKS5 connection response from the proxy server.
 * 
 * After requesting a connection to the target server, this function
 * handles the proxy's response. If successful, it transitions the handler
 * to ESTABLISHED state and invokes the setup callback to notify higher
 * layers that the connection is ready for use.
 * 
 * This is the final step in the SOCKS5 handshake process.
 * 
 * @param handler The SOCKS5 channel handler
 * @param slot The channel slot this handler belongs to
 * @param data Cursor pointing to the response data
 * @return AWS_OP_SUCCESS if processing succeeded, AWS_OP_ERR otherwise
 */
static int s_process_connect_response(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_cursor *data) {
    
    (void)slot;
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    uint64_t start_time = 0;
    
    if (socks5_handler->slot && socks5_handler->slot->channel) {
        aws_channel_current_clock_time(socks5_handler->slot->channel, &start_time);
    }
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Processing SOCKS5 connect response of size %zu bytes",
        (void *)handler,
        data->len);
    
    /* Log buffer details for comprehensive diagnostics */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: CONNECT phase - read_buffer details (buffer=%p, capacity=%zu, len=%zu)",
        (void *)handler,
        (void*)socks5_handler->read_buffer.buffer,
        socks5_handler->read_buffer.capacity,
        socks5_handler->read_buffer.len);
    
    /* Validate response format before processing */
    if (data->len < 4) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 CONNECT response format invalid - too short (%zu bytes, minimum 4 required)",
            (void *)handler,
            data->len);
            
        /* Use transition_state for consistent error handling */
        s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_ERROR, AWS_ERROR_INVALID_ARGUMENT);
        s_invoke_setup_callback_safely(socks5_handler, AWS_ERROR_INVALID_ARGUMENT);
        return AWS_OP_ERR;
    }
    
    /* Log response version and status code for debugging */
    if (data->len >= 2) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 CONNECT response - version=0x%02x, status=0x%02x",
            (void *)handler,
            data->ptr[0],
            data->ptr[1]);
    }
    
    /* Process the connection response */
    if (aws_socks5_read_connect_response(&socks5_handler->context, data)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 connection request failed, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        /* If we have status code information, log it for diagnostics */
        if (data->len >= 2) {
            uint8_t status = data->ptr[1];
            const char* status_str = "Unknown";
            
            /* Convert SOCKS5 status codes to readable strings */
            switch(status) {
                case 0: status_str = "Success"; break;
                case 1: status_str = "General failure"; break;
                case 2: status_str = "Connection not allowed"; break;
                case 3: status_str = "Network unreachable"; break;
                case 4: status_str = "Host unreachable"; break;
                case 5: status_str = "Connection refused"; break;
                case 6: status_str = "TTL expired"; break;
                case 7: status_str = "Command not supported"; break;
                case 8: status_str = "Address type not supported"; break;
            }
            
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: SOCKS5 server returned status code %d (%s)",
                (void *)handler,
                status,
                status_str);
        }
        
        /* Use transition_state for consistent error handling */
        s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_ERROR, error_code);
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        return AWS_OP_ERR;
    }
    
    /* Log successful connection with target details if available */
    struct aws_string * ctx_target_host_log =
    socks5_handler->context.endpoint_host;
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKS5,
        "id=%p: SOCKS5 connection to target host '%.*s:%d' established successfully",
        (void *)handler,
        (int)ctx_target_host_log->len,
        (const char *)ctx_target_host_log->bytes,
        socks5_handler->context.endpoint_port);
        
    /* Calculate handshake duration for performance metrics */
    uint64_t end_time = 0;
    if (socks5_handler->slot && socks5_handler->slot->channel) {
        aws_channel_current_clock_time(socks5_handler->slot->channel, &end_time);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: SOCKS5 connect response processing took %" PRIu64 "ns",
            (void *)handler,
            end_time - start_time);
    }
    
    /* Connection established, transition to established state */
    s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED, 0);
    
    /* Cancel any pending timeout task */
    if (socks5_handler->timeout_task_scheduled) {
        /* The task will remain in the event loop's task queue, but when it runs,
           it will check if we're in ESTABLISHED state and do nothing */
        socks5_handler->timeout_task_scheduled = false;
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: Connection established before timeout occurred, canceling timeout task",
            (void *)handler);
    }
    
    /* Debug handler setup callback and user data */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Callback %p, User data %p", 
        (void *)handler,
        (void *)(uintptr_t)socks5_handler->on_setup_completed, 
        socks5_handler->user_data);
    
    /* Check for composite context in user_data */
    if (socks5_handler->user_data != NULL) {
        struct {
            struct aws_socks5_proxy_options *socks5_options;
            void *original_user_data;
        } *composite_ctx = socks5_handler->user_data;
        
        /* If this looks like our composite context, print details */
        if (composite_ctx->socks5_options != NULL && 
            composite_ctx->original_user_data != NULL) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_SOCKS5,
                "id=%p: Found composite context: socks5_options=%p, original_user_data=%p",
                (void *)handler,
                (void*)composite_ctx->socks5_options,
                composite_ctx->original_user_data);
        }
    }
    
    /* Invoke the user callback with success */
    AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: Invoking setup callback with success status", (void *)handler);
    s_invoke_setup_callback_safely(socks5_handler, AWS_OP_SUCCESS);
    
    return AWS_OP_SUCCESS;
}

/* Process incoming data during handshake */
static void s_process_read_message(
    struct aws_channel_handler *handler, 
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: s_process_read_message called with message size %zu", 
        (void *)handler,
        message->message_data.len);
    
    /* Debug raw message data */
    if (message->message_data.len > 0) {
    }
    
    if (!handler || !slot || !message) {
        return; /* Nothing we can do without valid parameters */
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    
    if (!socks5_handler) {
        return; /* Can't process without a valid handler context */
    }
    
    /* Add the message data to our read buffer */
    struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
    
    /* Check if the read buffer is in a valid state */
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKS5,
        "id=%p: Read buffer state check - buffer=%p, capacity=%zu, len=%zu, allocator=%p",
        (void *)handler,
        (void*)socks5_handler->read_buffer.buffer, 
        socks5_handler->read_buffer.capacity,
        socks5_handler->read_buffer.len,
        (void*)socks5_handler->read_buffer.allocator);
    
    /* Fail immediately if the buffer is NULL */
    if (socks5_handler->read_buffer.buffer == NULL) {
        
        int error_code = AWS_ERROR_INVALID_STATE;
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: CRITICAL ERROR - read_buffer.buffer is NULL! Cannot append data",
            (void *)handler);
        
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = error_code;
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        aws_mem_release(message->allocator, message);
        return;
    }
    
    /* Ensure buffer has sufficient capacity */
    size_t needed_capacity = socks5_handler->read_buffer.len + message_cursor.len;
    if (s_ensure_buffer_capacity(&socks5_handler->read_buffer, socks5_handler->allocator, needed_capacity)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to ensure read buffer capacity",
            (void *)handler);
        return;
    }
    
    if (aws_byte_buf_append(
            &socks5_handler->read_buffer, 
            &message_cursor)) {
        
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to append to read buffer, error=%d (%s)",
            (void *)handler,
            error_code,
            aws_error_str(error_code));
        
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = error_code;
        s_invoke_setup_callback_safely(socks5_handler, error_code);
        aws_mem_release(message->allocator, message);
        return;
    }
        
    /* We've consumed the message, so we can release it */
    aws_mem_release(message->allocator, message);
    
    /* Process the data based on the current state */
    struct aws_byte_cursor data = aws_byte_cursor_from_buf(&socks5_handler->read_buffer);
    int result = AWS_OP_SUCCESS;
        
    switch (socks5_handler->channel_state) {
        case AWS_SOCKS5_CHANNEL_STATE_GREETING:
            if (data.len >= AWS_SOCKS5_GREETING_RESP_SIZE) {
                result = s_process_greeting_response(handler, slot, &data);
                
                /* Consume the processed data using memmove instead of temp buffer */
                size_t remaining_size = socks5_handler->read_buffer.len - AWS_SOCKS5_GREETING_RESP_SIZE;
                if (remaining_size > 0) {
                    /* Shift the remaining data to the beginning of the buffer */
                    memmove(socks5_handler->read_buffer.buffer, 
                            socks5_handler->read_buffer.buffer + AWS_SOCKS5_GREETING_RESP_SIZE, 
                            remaining_size);
                }
                /* Update the buffer length */
                socks5_handler->read_buffer.len = remaining_size;
            }
            break;
            
        case AWS_SOCKS5_CHANNEL_STATE_AUTH:
            if (data.len >= AWS_SOCKS5_AUTH_RESP_SIZE) {
                result = s_process_auth_response(handler, slot, &data);
                
                /* Consume the processed data using memmove instead of temp buffer */
                size_t remaining_size = socks5_handler->read_buffer.len - AWS_SOCKS5_AUTH_RESP_SIZE;
                if (remaining_size > 0) {
                    /* Shift the remaining data to the beginning of the buffer */
                    memmove(socks5_handler->read_buffer.buffer, 
                            socks5_handler->read_buffer.buffer + AWS_SOCKS5_AUTH_RESP_SIZE, 
                            remaining_size);
                }
                /* Update the buffer length */
                socks5_handler->read_buffer.len = remaining_size;
                
                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKS5,
                    "id=%p: AUTH state - After memmove: read_buffer (buffer=%p, capacity=%zu, len=%zu)",
                    (void *)handler,
                    (void*)socks5_handler->read_buffer.buffer, 
                    socks5_handler->read_buffer.capacity, 
                    socks5_handler->read_buffer.len);
            }
            break;
            
        case AWS_SOCKS5_CHANNEL_STATE_CONNECT:
            /* For connect response, we need to parse the first few bytes to determine size */
            AWS_LOGF_TRACE(
                AWS_LS_IO_SOCKS5,
                "id=%p: Processing CONNECT response, data length %zu",
                (void *)handler,
                data.len);
            
            /* Dump the response bytes for debugging */
            if (data.len > 0) {
            }
            
            if (data.len >= 4) { /* At least VER(1) + REP(1) + RSV(1) + ATYP(1) */
                uint8_t ver = data.ptr[0];
                uint8_t rep = data.ptr[1];
                uint8_t atype = data.ptr[3];
                
                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKS5,
                    "id=%p: SOCKS5 response - VER: %d, REP: %d, ATYP: %d",
                    (void *)handler,
                    ver, rep, atype);
                
                size_t addr_size = 0;
                
                /* Determine the address size based on the address type */
                switch (atype) {
                    case AWS_SOCKS5_ATYP_DOMAIN:
                        if (data.len >= 5) { /* Check if we can read the domain length byte */
                            uint8_t dom_len = data.ptr[4];
                            addr_size = 1 + dom_len; /* Length byte + domain */
                            AWS_LOGF_TRACE(
                                AWS_LS_IO_SOCKS5,
                                "id=%p: Domain address type with length %u",
                                (void *)handler,
                                dom_len);
                        } else {
                            /* Wait for more data */
                            AWS_LOGF_TRACE(
                                AWS_LS_IO_SOCKS5,
                                "id=%p: Waiting for more data to read domain length",
                                (void *)handler);
                            return;
                        }
                        break;
                        
                    case AWS_SOCKS5_ATYP_IPV4:
                        addr_size = 4;
                        AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: IPv4 address type", (void *)handler);
                        break;
                        
                    case AWS_SOCKS5_ATYP_IPV6:
                        addr_size = 16;
                        AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: IPv6 address type", (void *)handler);
                        break;
                        
                    default:
                        AWS_LOGF_WARN(
                            AWS_LS_IO_SOCKS5, 
                            "id=%p: Unknown address type: %d", 
                            (void *)handler, 
                            atype);
                        /* Unknown address type, try to proceed with minimal parsing */
                        addr_size = 1;
                        break;
                }
                
                /* Calculate the full response size */
                size_t response_size = 4 + addr_size + 2; /* Header + address + port */
                
                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKS5,
                    "id=%p: Expected response size: %zu, current data size: %zu", 
                    (void *)handler,
                    response_size, data.len);
                
                /* Check if we have the complete response */
                if (addr_size > 0 && data.len >= response_size) {
                    result = s_process_connect_response(handler, slot, &data);
                    
                    /* If successful, we don't need to shift the buffer because
                       we're now in established state and will forward any remaining data */
                    if (result == AWS_OP_SUCCESS && 
                        socks5_handler->channel_state == AWS_SOCKS5_CHANNEL_STATE_ESTABLISHED) {
                        
                        /* Calculate the size of the SOCKS5 response */
                        size_t response_size = 4 + addr_size + 2; /* Header + address + port */
                        
                        /* If there's more data after the SOCKS5 response, we need to forward it */
                        if (socks5_handler->read_buffer.len > response_size) {
                            AWS_LOGF_INFO(
                                AWS_LS_IO_SOCKS5,
                                "id=%p: Found %zu bytes of trailing data after SOCKS5 handshake completion",
                                (void *)handler,
                                socks5_handler->read_buffer.len - response_size);
                            
                            /* Create a new message with the remaining data for forwarding */
                            struct aws_io_message *forward_message = aws_channel_acquire_message_from_pool(
                                slot->channel,
                                AWS_IO_MESSAGE_APPLICATION_DATA,
                                socks5_handler->read_buffer.len - response_size);
                            
                            if (forward_message) {
                                /* Copy the remaining data after the SOCKS5 response */
                                if (aws_byte_buf_write(
                                        &forward_message->message_data, 
                                        socks5_handler->read_buffer.buffer + response_size, 
                                        socks5_handler->read_buffer.len - response_size)) {
                                    
                                    AWS_LOGF_DEBUG(
                                        AWS_LS_IO_SOCKS5,
                                        "id=%p: Forwarding %zu bytes of application data received alongside final SOCKS5 response",
                                        (void *)handler,
                                        forward_message->message_data.len);
                                    
                                    /* We need to delay sending this message until after the setup callback
                                     * completes to ensure higher layer handlers are properly installed */
                                    
                                    /* Schedule a task to forward the data after the current event loop iteration */
                                    struct aws_channel_task *forward_task = aws_mem_calloc(
                                        socks5_handler->allocator, 1, sizeof(struct aws_channel_task));
                                    
                                    if (forward_task) {
                                        struct {
                                            struct aws_channel_slot *slot;
                                            struct aws_io_message *message;
                                            struct aws_allocator *allocator;
                                        } *forward_ctx = aws_mem_calloc(
                                            socks5_handler->allocator, 1, sizeof(*forward_ctx));
                                        
                                        if (forward_ctx) {
                                            forward_ctx->slot = slot;
                                            forward_ctx->message = forward_message;
                                            forward_ctx->allocator = socks5_handler->allocator;
                                            
                                            aws_channel_task_init(
                                                forward_task,
                                                s_forward_pending_data_task,
                                                forward_ctx,
                                                "socks5_forward_pending_data");
                                            
                                            aws_channel_schedule_task_now(slot->channel, forward_task);
                                            
                                            AWS_LOGF_TRACE(
                                                AWS_LS_IO_SOCKS5,
                                                "id=%p: Scheduled task to forward pending data",
                                                (void *)handler);
                                        } else {
                                            aws_mem_release(socks5_handler->allocator, forward_task);
                                            aws_mem_release(forward_message->allocator, forward_message);
                                        }
                                    } else {
                                        aws_mem_release(forward_message->allocator, forward_message);
                                    }
                                } else {
                                    AWS_LOGF_ERROR(
                                        AWS_LS_IO_SOCKS5,
                                        "id=%p: Failed to write remaining data to forward message",
                                        (void *)handler);
                                    aws_mem_release(forward_message->allocator, forward_message);
                                }
                            } else {
                                AWS_LOGF_ERROR(
                                    AWS_LS_IO_SOCKS5,
                                    "id=%p: Failed to acquire message for forwarding remaining data",
                                    (void *)handler);
                            }
                            
                            /* Reset the buffer now that we've handled the remaining data */
                            socks5_handler->read_buffer.len = 0;
                        } else {
                            /* No remaining data, simply reset the buffer length to 0 but keep the capacity */
                            socks5_handler->read_buffer.len = 0;
                        }
                    }
                }
            }
            break;
            
        default:
            /* In any other state, do nothing with the data */
            break;
    }
    
    if (result != AWS_OP_SUCCESS) {
        /* An error occurred while processing the message */
        socks5_handler->channel_state = AWS_SOCKS5_CHANNEL_STATE_ERROR;
        socks5_handler->error_code = aws_last_error();
    }
}

/* Public API functions */

struct aws_channel_handler *aws_socks5_channel_handler_new(
    struct aws_allocator *allocator,
    const struct aws_socks5_proxy_options *proxy_options,
    struct aws_byte_cursor endpoint_host,
    uint16_t endpoint_port,
    enum aws_socks5_address_type endpoint_address_type,
    aws_channel_on_setup_completed_fn *on_setup_completed,
    void *user_data) {
    

    AWS_ASSERT(allocator);
    AWS_ASSERT(proxy_options);
    
    if (!allocator) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }
    
    if (!proxy_options) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }
    
    if (!endpoint_host.ptr || endpoint_host.len == 0) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }
    
    struct aws_socks5_channel_handler *socks5_handler = aws_mem_calloc(
        allocator, 1, sizeof(struct aws_socks5_channel_handler));
    
    if (!socks5_handler) {
        return NULL;
    }
    
    AWS_ZERO_STRUCT(*socks5_handler);
    socks5_handler->allocator = allocator;
    
    /* Initialize the SOCKS5 context */
    if (aws_socks5_context_init(
            &socks5_handler->context,
            allocator,
            proxy_options,
            endpoint_host,
            endpoint_port,
            endpoint_address_type)) {
        goto on_error;
    }
    
    /* Initialize the handler */
    socks5_handler->handler.impl = socks5_handler;
    socks5_handler->handler.vtable = &s_socks5_handler_vtable;
    socks5_handler->on_setup_completed = on_setup_completed;
    socks5_handler->user_data = user_data;
    s_transition_state(socks5_handler, AWS_SOCKS5_CHANNEL_STATE_INIT, 0);
    socks5_handler->process_incoming_data = false;
    
    /* Initialize send buffer */
    if (aws_byte_buf_init(&socks5_handler->send_buffer, allocator, 256)) {
        goto on_error;
    }
    
    /* Initialize read buffer */
    if (aws_byte_buf_init(&socks5_handler->read_buffer, allocator, 256)) {
        goto on_error;
    }
    
    /* Set the connection timeout */
    socks5_handler->connect_timeout_ns =
        aws_timestamp_convert(proxy_options->connection_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);

    return &socks5_handler->handler;
    
on_error:
    s_socks5_handler_destroy(&socks5_handler->handler);
    return NULL;
}

/**
 * Custom TLS negotiation result callback that chains to the original callback
 * and then calls the setup callback with the final result.
 * 
 * This function is critical for SOCKS5+TLS integration as it ensures proper
 * callback chaining and resource cleanup after TLS negotiation completes.
 */
static void s_release_bootstrap_resources(struct aws_socks5_bootstrap *bootstrap);

static void s_socks5_tls_on_negotiation_result(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int error_code,
    void *user_data) {
    
    struct aws_socks5_bootstrap *socks5_bootstrap = (struct aws_socks5_bootstrap *)user_data;
    
    if (!socks5_bootstrap) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: TLS negotiation callback called with NULL bootstrap");
        return;
    }
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: TLS negotiation completed with result %d (%s)",
        (void *)socks5_bootstrap,
        error_code,
        aws_error_str(error_code));
        
    /* Make local copies of all values we need, since bootstrap might be freed */
    struct aws_client_bootstrap *client_bootstrap = socks5_bootstrap->bootstrap;
    void *callback_user_data = socks5_bootstrap->user_data;
    aws_client_bootstrap_on_channel_event_fn *setup_callback = socks5_bootstrap->setup_callback;
    aws_tls_on_negotiation_result_fn *original_on_negotiation_result = socks5_bootstrap->original_on_negotiation_result;
    void *original_tls_user_data = socks5_bootstrap->original_tls_user_data;
    
    /* First call the original TLS negotiation callback if set */
    if (original_on_negotiation_result) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "id=%p: Calling original TLS negotiation callback %p with user data %p",
            (void *)socks5_bootstrap,
            (void *)(uintptr_t)original_on_negotiation_result,
            original_tls_user_data);
            
        original_on_negotiation_result(handler, slot, error_code, original_tls_user_data);
    }
    
    /* Always call the setup callback regardless of success/failure to ensure proper completion */
    if (setup_callback) {
        if (error_code != AWS_ERROR_SUCCESS) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: TLS negotiation failed with error %d (%s), notifying client",
                (void *)socks5_bootstrap,
                error_code,
                aws_error_str(error_code));
                
            /* For failures, pass NULL channel to indicate connection failed */
            setup_callback(client_bootstrap, error_code, NULL, callback_user_data);
        } else {
            AWS_LOGF_INFO(
                AWS_LS_IO_SOCKS5,
                "id=%p: TLS negotiation successful, calling setup callback to complete connection",
                (void *)socks5_bootstrap);

            setup_callback(client_bootstrap, AWS_ERROR_SUCCESS, slot->channel, callback_user_data);
        }
    }
    
    /* Release resources but keep bootstrap alive for the shutdown callback */
    s_release_bootstrap_resources(socks5_bootstrap);
}

/**
 * Helper function to install a TLS handler after SOCKS5 setup completes successfully.
 * 
 * This function extracts the TLS handler installation logic from s_on_socks5_setup_completed
 * to make the code more maintainable.
 */
static int s_install_tls_handler_after_socks5(
    struct aws_channel *channel,
    struct aws_socks5_bootstrap *bootstrap) {
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5, 
        "id=%p: Installing TLS handler after SOCKS5 handshake", 
        (void *)bootstrap);
        
    /* Set our custom TLS negotiation result callback */
    bootstrap->tls_options->on_negotiation_result = s_socks5_tls_on_negotiation_result;
    bootstrap->tls_options->user_data = bootstrap;
    
    /* Set up TLS handler */
    struct aws_channel_slot *tls_slot = aws_channel_slot_new(channel);
    if (!tls_slot) {
        int err_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, 
            "id=%p: Failed to create TLS slot, error=%d (%s)", 
            (void *)bootstrap, 
            err_code,
            aws_error_str(err_code));
        return err_code;
    }
    
    /* Create TLS handler using stored TLS options */
    struct aws_channel_handler *tls_handler = aws_tls_client_handler_new(
        bootstrap->allocator, bootstrap->tls_options, tls_slot);
    
    if (!tls_handler) {
        int err_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, 
            "id=%p: Failed to create TLS handler, error=%d (%s)", 
            (void *)bootstrap, 
            err_code,
            aws_error_str(err_code));
        
        aws_channel_slot_remove(tls_slot);
        return err_code;
    }
    
    /* Add TLS handler to channel */
    aws_channel_slot_insert_end(channel, tls_slot);
    
    if (aws_channel_slot_set_handler(tls_slot, tls_handler)) {
        int err_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, 
            "id=%p: Failed to set TLS handler on slot, error=%d (%s)", 
            (void *)bootstrap, 
            err_code,
            aws_error_str(err_code));
        return err_code;
    }
    
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5, 
        "id=%p: Starting TLS negotiation after SOCKS5 handshake", 
        (void *)bootstrap);
    
    /* Start TLS negotiation - NOW it's safe to begin TLS handshake
     * since SOCKS5 tunnel is established */
    if (aws_tls_client_handler_start_negotiation(tls_handler)) {
        int err_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, 
            "id=%p: Failed to start TLS negotiation, error=%d (%s)", 
            (void *)bootstrap, 
            err_code,
            aws_error_str(err_code));
        return err_code;
    }
    
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKS5, 
        "id=%p: TLS handler installed and negotiation started after SOCKS5 handshake", 
        (void *)bootstrap);
        
    return AWS_OP_SUCCESS;
}

/**
 * Releases dynamically allocated members held by the bootstrap without freeing the struct itself.
 * This allows the bootstrap wrapper to remain alive for shutdown callbacks while avoiding leaks.
 */
static void s_release_bootstrap_resources(struct aws_socks5_bootstrap *bootstrap) {
    if (!bootstrap) {
        return;
    }
    
    struct aws_allocator *allocator = bootstrap->allocator;
    
    /* Clean up TLS options if present */
    if (bootstrap->tls_options) {
        aws_tls_connection_options_clean_up(bootstrap->tls_options);
        aws_mem_release(allocator, bootstrap->tls_options);
        bootstrap->tls_options = NULL;
        bootstrap->use_tls = false;
        bootstrap->original_on_negotiation_result = NULL;
        bootstrap->original_tls_user_data = NULL;
    }
    
    /* Clean up SOCKS5 options if present */
    if (bootstrap->socks5_proxy_options) {
        aws_socks5_proxy_options_clean_up(bootstrap->socks5_proxy_options);
        aws_mem_release(allocator, bootstrap->socks5_proxy_options);
        bootstrap->socks5_proxy_options = NULL;
    }

    if (bootstrap->pending_channel) {
        aws_channel_release_hold(bootstrap->pending_channel);
        bootstrap->pending_channel = NULL;
    }

    if (bootstrap->endpoint_host) {
        aws_string_destroy(bootstrap->endpoint_host);
        bootstrap->endpoint_host = NULL;
    }

    if (bootstrap->original_endpoint_host) {
        aws_string_destroy(bootstrap->original_endpoint_host);
        bootstrap->original_endpoint_host = NULL;
    }

    bootstrap->endpoint_ready = false;
    bootstrap->resolution_in_progress = false;
    bootstrap->resolution_error_code = AWS_ERROR_SUCCESS;
    bootstrap->resolution_task_scheduled = false;
    bootstrap->resolution_failure_task_scheduled = false;
}

/**
 * Helper function to clean up a bootstrap structure and its associated resources
 */
static void s_destroy_bootstrap(struct aws_socks5_bootstrap *bootstrap) {
    if (!bootstrap) {
        return;
    }

    s_release_bootstrap_resources(bootstrap);
    aws_mutex_clean_up(&bootstrap->lock);
    aws_mem_release(bootstrap->allocator, bootstrap);
}

static void s_cleanup_bootstrap(struct aws_socks5_bootstrap *bootstrap) {
    if (!bootstrap) {
        return;
    }

    s_release_bootstrap_resources(bootstrap);

    bool defer_cleanup = false;

    aws_mutex_lock(&bootstrap->lock);
    if (bootstrap->resolution_in_progress) {
        /* Defer destruction until the resolver callback runs so it can drain outstanding tasks without touching freed memory */
        bootstrap->cleanup_pending = true;
        defer_cleanup = true;
    } else {
        bootstrap->cleanup_pending = false;
    }
    aws_mutex_unlock(&bootstrap->lock);

    if (defer_cleanup) {
        return;
    }

    s_destroy_bootstrap(bootstrap);
}

/**
 * Called when the SOCKS5 handshake completes.
 * If TLS is requested, this function will install the TLS handler.
 * Otherwise, it will call the setup callback directly.
 */
static void s_on_socks5_setup_completed(
    struct aws_channel *channel,
    int error_code,
    void *user_data)
{
    struct aws_socks5_bootstrap *bootstrap = (struct aws_socks5_bootstrap *)user_data;

    if (!bootstrap) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: s_on_socks5_setup_completed called with NULL bootstrap");
        return;
    }

    /* Make a local copy of the data we need in case bootstrap gets freed */
    struct aws_client_bootstrap *client_bootstrap = bootstrap->bootstrap;
    void *callback_user_data = bootstrap->user_data;
    aws_client_bootstrap_on_channel_event_fn *setup_callback = bootstrap->setup_callback;
    
    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, 
            "id=%p: SOCKS5 handshake failed with error_code=%d (%s)", 
            (void *)bootstrap, 
            error_code,
            aws_error_str(error_code));
        
        /* Call the original callback with the error */
        if (setup_callback) {
            setup_callback(client_bootstrap, error_code, NULL, callback_user_data);
        }
        
        s_release_bootstrap_resources(bootstrap);
        return;
    }

    /* SOCKS5 handshake successful */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5, 
        "id=%p: SOCKS5 handshake completed successfully", 
        (void *)bootstrap);
    
    /* If TLS is requested, install TLS handler now that SOCKS5 is established */
    if (bootstrap->use_tls && bootstrap->tls_options) {
        int result = s_install_tls_handler_after_socks5(channel, bootstrap);
        if (result != AWS_OP_SUCCESS) {
            /* Failed to install TLS handler, call setup callback with error */
            if (setup_callback) {
                setup_callback(client_bootstrap, result, NULL, callback_user_data);
            }
            
            s_release_bootstrap_resources(bootstrap);
        }
        /* Note: bootstrap is NOT cleaned up here on success, as that will be done 
         * in the TLS negotiation result callback */
    } else {
        /* No TLS needed, call the original setup callback directly */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5, 
            "id=%p: No TLS requested, calling original callback", 
            (void *)bootstrap);
        
        if (setup_callback) {
            setup_callback(client_bootstrap, AWS_ERROR_SUCCESS, channel, callback_user_data);
        }
        
        s_release_bootstrap_resources(bootstrap);
    }
}

static void s_socks5_socket_channel_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data)
{
    struct aws_socks5_bootstrap *socks5_bootstrap = (struct aws_socks5_bootstrap *)user_data;
    AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: Context=%p", (void *)channel, (void*)socks5_bootstrap);
    AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: setup_callback=%p", (void *)channel, (void *)(uintptr_t)socks5_bootstrap->setup_callback);
    AWS_LOGF_TRACE(AWS_LS_IO_SOCKS5, "id=%p: original_user_data=%p", (void *)channel, (void*)socks5_bootstrap->user_data);

    if (error_code != AWS_ERROR_SUCCESS || channel == NULL) {
        if (socks5_bootstrap->setup_callback) {
            socks5_bootstrap->setup_callback(bootstrap, error_code, NULL, socks5_bootstrap->user_data);
        }
        if (channel == NULL) {
            s_cleanup_bootstrap(socks5_bootstrap);
        } else {
            s_release_bootstrap_resources(socks5_bootstrap);
        }
        return;
    }

    bool endpoint_ready = false;
    bool resolution_in_progress = false;
    int resolution_error = AWS_ERROR_SUCCESS;

    aws_mutex_lock(&socks5_bootstrap->lock);
    endpoint_ready = socks5_bootstrap->endpoint_ready;
    resolution_in_progress = socks5_bootstrap->resolution_in_progress;
    resolution_error = socks5_bootstrap->resolution_error_code;

    if (!endpoint_ready && resolution_error == AWS_ERROR_SUCCESS && resolution_in_progress) {
        /* DNS still running: hold the channel so the callback can resume the handshake later */
        if (!socks5_bootstrap->pending_channel) {
            socks5_bootstrap->pending_channel = channel;
            aws_channel_acquire_hold(channel);
        }
        aws_mutex_unlock(&socks5_bootstrap->lock);
        return;
    }

    if (error_code != AWS_ERROR_SUCCESS) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Client-side resolution failed for '%s' with error %d (%s)",
            (void *)socks5_bootstrap,
            socks5_bootstrap->original_endpoint_host
                ? aws_string_c_str(socks5_bootstrap->original_endpoint_host)
                : "(null)",
            error_code,
            aws_error_str(error_code));
    }

    aws_mutex_unlock(&socks5_bootstrap->lock);

    if (resolution_error != AWS_ERROR_SUCCESS) {
        if (socks5_bootstrap->setup_callback) {
            socks5_bootstrap->setup_callback(bootstrap, resolution_error, NULL, socks5_bootstrap->user_data);
        }
        aws_channel_shutdown(channel, resolution_error);
        s_release_bootstrap_resources(socks5_bootstrap);
        return;
    }

    if (!endpoint_ready) {
        int err_code = AWS_ERROR_INVALID_STATE;
        if (socks5_bootstrap->setup_callback) {
            socks5_bootstrap->setup_callback(bootstrap, err_code, NULL, socks5_bootstrap->user_data);
        }
        aws_channel_shutdown(channel, err_code);
        s_release_bootstrap_resources(socks5_bootstrap);
        return;
    }

    if (s_socks5_bootstrap_begin_handshake(socks5_bootstrap, channel)) {
        int err_code = aws_last_error();
        if (socks5_bootstrap->setup_callback) {
            socks5_bootstrap->setup_callback(bootstrap, err_code, NULL, socks5_bootstrap->user_data);
        }
        s_release_bootstrap_resources(socks5_bootstrap);
        return;
    }
    /* At this point, the SOCKS5 handler will invoke the setup callback. Final cleanup happens during shutdown. */
}

static int s_socks5_bootstrap_begin_handshake(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    struct aws_channel *channel) {

    if (!socks5_bootstrap || !channel) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_channel_slot *slot = aws_channel_get_first_slot(channel);
    if (!slot) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    struct aws_byte_cursor endpoint_host_cursor = aws_byte_cursor_from_array(
        socks5_bootstrap->endpoint_host ? aws_string_bytes(socks5_bootstrap->endpoint_host) : NULL,
        socks5_bootstrap->endpoint_host ? socks5_bootstrap->endpoint_host->len : 0);

    if (endpoint_host_cursor.len == 0 || endpoint_host_cursor.ptr == NULL) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_channel_handler *socks5_handler = aws_socks5_channel_handler_new(
        socks5_bootstrap->allocator,
        socks5_bootstrap->socks5_proxy_options,
        endpoint_host_cursor,
        socks5_bootstrap->endpoint_port,
        socks5_bootstrap->endpoint_address_type,
        s_on_socks5_setup_completed,
        socks5_bootstrap);
    if (!socks5_handler) {
        return AWS_OP_ERR;
    }

    struct aws_channel_slot *socks5_slot = aws_channel_slot_new(channel);
    if (!socks5_slot) {
        aws_channel_handler_destroy(socks5_handler);
        return AWS_OP_ERR;
    }

    aws_channel_slot_insert_right(slot, socks5_slot);
    socks5_handler->slot = socks5_slot;

    struct aws_socks5_channel_handler *impl_ptr = socks5_handler->impl;
    if (impl_ptr) {
        impl_ptr->slot = socks5_slot;
        impl_ptr->user_data = socks5_bootstrap;
    }

    if (aws_channel_slot_set_handler(socks5_slot, socks5_handler)) {
        aws_channel_slot_remove(socks5_slot);
        return AWS_OP_ERR;
    }

    if (aws_socks5_channel_handler_start_handshake(socks5_handler)) {
        aws_channel_slot_remove(socks5_slot);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_socks5_bootstrap_resolution_success_task(
    struct aws_channel_task *task,
    void *arg,
    enum aws_task_status status) {
    (void)task;

    struct aws_socks5_bootstrap *socks5_bootstrap = arg;
    if (!socks5_bootstrap) {
        return;
    }

    struct aws_channel *channel = NULL;

    aws_mutex_lock(&socks5_bootstrap->lock);
    socks5_bootstrap->resolution_task_scheduled = false;
    channel = socks5_bootstrap->pending_channel;
    socks5_bootstrap->pending_channel = NULL;
    aws_mutex_unlock(&socks5_bootstrap->lock);

    if (!channel) {
        return;
    }

    /* Defer handshake work to the channel's event-loop thread */
    if (status != AWS_TASK_STATUS_RUN_READY) {
        aws_channel_release_hold(channel);
        return;
    }

    if (s_socks5_bootstrap_begin_handshake(socks5_bootstrap, channel)) {
        int err_code = aws_last_error();
        if (socks5_bootstrap->setup_callback) {
            socks5_bootstrap->setup_callback(
                socks5_bootstrap->bootstrap,
                err_code,
                NULL,
                socks5_bootstrap->user_data);
        }
        aws_channel_shutdown(channel, err_code);
        s_release_bootstrap_resources(socks5_bootstrap);
    }

    aws_channel_release_hold(channel);
}

static void s_socks5_bootstrap_resolution_failure_task(
    struct aws_channel_task *task,
    void *arg,
    enum aws_task_status status) {
    (void)task;
    struct aws_socks5_bootstrap *socks5_bootstrap = arg;
    if (!socks5_bootstrap) {
        return;
    }

    struct aws_channel *channel = NULL;
    int error_code = socks5_bootstrap->resolution_error_code;
    if (error_code == AWS_ERROR_SUCCESS) {
        error_code = AWS_IO_DNS_INVALID_NAME;
    }

    aws_mutex_lock(&socks5_bootstrap->lock);
    socks5_bootstrap->resolution_failure_task_scheduled = false;
    channel = socks5_bootstrap->pending_channel;
    socks5_bootstrap->pending_channel = NULL;
    aws_mutex_unlock(&socks5_bootstrap->lock);

    /* Propagate DNS failure on the channel thread to keep shutdown ordering intact */
    if (channel && status == AWS_TASK_STATUS_RUN_READY) {
        aws_channel_shutdown(channel, error_code);
        aws_channel_release_hold(channel);
    } else if (channel) {
        aws_channel_release_hold(channel);
    }

    if (socks5_bootstrap->setup_callback) {
        socks5_bootstrap->setup_callback(
            socks5_bootstrap->bootstrap,
            error_code,
            NULL,
            socks5_bootstrap->user_data);
    }

    s_release_bootstrap_resources(socks5_bootstrap);
}

/* Handle channel shutdown */
static void s_socks5_socket_channel_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    struct aws_socks5_bootstrap *socks5_bootstrap = (struct aws_socks5_bootstrap *)user_data;
    if (!socks5_bootstrap) {
        return;
    }

    if (socks5_bootstrap->shutdown_callback) {
        socks5_bootstrap->shutdown_callback(bootstrap, error_code, channel, socks5_bootstrap->user_data);
    }

    s_cleanup_bootstrap(socks5_bootstrap);
}

static void s_socks5_bootstrap_create_channel_options(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    struct aws_socket_channel_bootstrap_options *channel_options)
{
    channel_options->host_name = aws_string_c_str(socks5_bootstrap->socks5_proxy_options->host);
    channel_options->port = socks5_bootstrap->socks5_proxy_options->port;
    channel_options->setup_callback = s_socks5_socket_channel_setup;
    channel_options->shutdown_callback = s_socks5_socket_channel_shutdown;
    channel_options->user_data = socks5_bootstrap;
    channel_options->tls_options = NULL; // Handled internally after SOCKS5 handshake
}

static int s_socks5_bootstrap_set_socks5_proxy_options(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    struct aws_allocator *allocator,
    const struct aws_socks5_proxy_options *source_proxy_options,
    const char *host_name,
    uint16_t port
) 
{
    if (!source_proxy_options) {
        return AWS_OP_SUCCESS;
    }

    struct aws_socks5_proxy_options * socks5_proxy_options =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_options));
    if (!socks5_proxy_options) {
        return AWS_OP_ERR;
    }

    if (aws_socks5_proxy_options_copy(socks5_proxy_options, source_proxy_options)) {
        aws_socks5_proxy_options_clean_up(socks5_proxy_options);
        aws_mem_release(allocator, socks5_proxy_options);
        return AWS_OP_ERR;
    }

    if (!host_name || host_name[0] == '\0') {
        aws_socks5_proxy_options_clean_up(socks5_proxy_options);
        aws_mem_release(allocator, socks5_proxy_options);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_byte_cursor endpoint_host_cursor = aws_byte_cursor_from_c_str(host_name);

    aws_string_destroy(socks5_bootstrap->endpoint_host);
    socks5_bootstrap->endpoint_host = NULL;
    aws_string_destroy(socks5_bootstrap->original_endpoint_host);
    socks5_bootstrap->original_endpoint_host = NULL;

    socks5_bootstrap->endpoint_port = port;
    enum aws_socks5_address_type inferred_type =
        aws_socks5_infer_address_type(endpoint_host_cursor, AWS_SOCKS5_ATYP_DOMAIN);
    socks5_bootstrap->host_resolution_mode =
        aws_socks5_proxy_options_get_host_resolution_mode(socks5_proxy_options);
    socks5_bootstrap->resolution_error_code = AWS_ERROR_SUCCESS;
    socks5_bootstrap->endpoint_ready =
        socks5_bootstrap->host_resolution_mode != AWS_SOCKS5_HOST_RESOLUTION_CLIENT;
    socks5_bootstrap->resolution_in_progress = false;

    if (socks5_bootstrap->host_resolution_mode == AWS_SOCKS5_HOST_RESOLUTION_CLIENT &&
        inferred_type != AWS_SOCKS5_ATYP_DOMAIN) {
        socks5_bootstrap->endpoint_host =
            aws_string_new_from_cursor(allocator, &endpoint_host_cursor);
        if (!socks5_bootstrap->endpoint_host) {
            aws_socks5_proxy_options_clean_up(socks5_proxy_options);
            aws_mem_release(allocator, socks5_proxy_options);
            return AWS_OP_ERR;
        }
        socks5_bootstrap->original_endpoint_host =
            aws_string_new_from_cursor(allocator, &endpoint_host_cursor);
        if (!socks5_bootstrap->original_endpoint_host) {
            aws_string_destroy(socks5_bootstrap->endpoint_host);
            socks5_bootstrap->endpoint_host = NULL;
            aws_socks5_proxy_options_clean_up(socks5_proxy_options);
            aws_mem_release(allocator, socks5_proxy_options);
            return AWS_OP_ERR;
        }
        socks5_bootstrap->endpoint_address_type = inferred_type;
        socks5_bootstrap->endpoint_ready = true;
    } else if (socks5_bootstrap->host_resolution_mode == AWS_SOCKS5_HOST_RESOLUTION_CLIENT) {
        socks5_bootstrap->original_endpoint_host =
            aws_string_new_from_cursor(allocator, &endpoint_host_cursor);
        if (!socks5_bootstrap->original_endpoint_host) {
            aws_socks5_proxy_options_clean_up(socks5_proxy_options);
            aws_mem_release(allocator, socks5_proxy_options);
            return AWS_OP_ERR;
        }
        socks5_bootstrap->endpoint_address_type = AWS_SOCKS5_ATYP_DOMAIN;
        socks5_bootstrap->endpoint_ready = false;
    } else {
        socks5_bootstrap->endpoint_host =
            aws_string_new_from_cursor(allocator, &endpoint_host_cursor);
        if (!socks5_bootstrap->endpoint_host) {
            aws_socks5_proxy_options_clean_up(socks5_proxy_options);
            aws_mem_release(allocator, socks5_proxy_options);
            return AWS_OP_ERR;
        }
        socks5_bootstrap->endpoint_address_type = inferred_type;
    }

    socks5_bootstrap->socks5_proxy_options = socks5_proxy_options;

    return AWS_OP_SUCCESS;
}

static int s_socks5_bootstrap_set_tls_options(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    struct aws_allocator *allocator,
    const struct aws_tls_connection_options *tls_options) 
{
    if (!tls_options) {
        return AWS_OP_SUCCESS;
    }
    socks5_bootstrap->tls_options =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_tls_connection_options));
    if (!socks5_bootstrap->tls_options) {
        return AWS_OP_ERR;
    }
    socks5_bootstrap->original_on_negotiation_result = tls_options->on_negotiation_result;
    socks5_bootstrap->original_tls_user_data = tls_options->user_data;
    if (aws_tls_connection_options_copy(socks5_bootstrap->tls_options, tls_options)) {
        aws_tls_connection_options_clean_up(socks5_bootstrap->tls_options);
        aws_mem_release(allocator, socks5_bootstrap->tls_options);
        socks5_bootstrap->tls_options = NULL;
        return AWS_OP_ERR;
    }
    socks5_bootstrap->use_tls = true;
    return AWS_OP_SUCCESS;
}

static int s_socks5_bootstrap_start_endpoint_resolution(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    const struct aws_socket_channel_bootstrap_options *channel_options) {

    if (!socks5_bootstrap || !channel_options) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (socks5_bootstrap->host_resolution_mode != AWS_SOCKS5_HOST_RESOLUTION_CLIENT || socks5_bootstrap->endpoint_ready) {
        return AWS_OP_SUCCESS;
    }

    if (!socks5_bootstrap->original_endpoint_host) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_client_bootstrap *client_bootstrap = channel_options->bootstrap;
    if (!client_bootstrap || !client_bootstrap->host_resolver) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    /* Prefer per-request overrides, otherwise fall back to bootstrap defaults */
    const struct aws_host_resolution_config *config_to_use =
        channel_options->host_resolution_override_config;

    if (config_to_use) {
        socks5_bootstrap->host_resolution_config = *config_to_use;
        socks5_bootstrap->has_host_resolution_override = true;
        config_to_use = &socks5_bootstrap->host_resolution_config;
    } else {
        socks5_bootstrap->host_resolution_config = client_bootstrap->host_resolver_config;
        socks5_bootstrap->has_host_resolution_override = false;
        config_to_use = &client_bootstrap->host_resolver_config;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=%p: Starting client-side resolution for endpoint '%s'",
        (void *)socks5_bootstrap,
        aws_string_c_str(socks5_bootstrap->original_endpoint_host));

    /* Track outstanding work so the setup path can defer the handshake */
    socks5_bootstrap->resolution_error_code = AWS_ERROR_SUCCESS;
    socks5_bootstrap->resolution_in_progress = true;

    if (aws_host_resolver_resolve_host(
            client_bootstrap->host_resolver,
            socks5_bootstrap->original_endpoint_host,
            s_socks5_on_host_resolved,
            config_to_use,
            socks5_bootstrap)) {
        socks5_bootstrap->resolution_in_progress = false;
        socks5_bootstrap->resolution_error_code = aws_last_error();
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_socks5_on_host_resolved(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {
    (void)resolver;
    (void)host_name;

    struct aws_socks5_bootstrap *socks5_bootstrap = user_data;
    if (!socks5_bootstrap) {
        return;
    }

    struct aws_channel *channel_for_success = NULL;
    struct aws_channel *channel_for_failure = NULL;
    struct aws_channel_task *success_task = NULL;
    struct aws_channel_task *failure_task = NULL;

    int error_code = err_code;

    aws_mutex_lock(&socks5_bootstrap->lock);
    socks5_bootstrap->resolution_in_progress = false;

    if (error_code != AWS_ERROR_SUCCESS) {
        socks5_bootstrap->resolution_error_code = error_code;
    } else {
        size_t address_count = host_addresses ? aws_array_list_length(host_addresses) : 0;
        if (!host_addresses || address_count == 0) {
            error_code = AWS_IO_DNS_INVALID_NAME;
            socks5_bootstrap->resolution_error_code = error_code;
        } else {
            const struct aws_host_address *chosen_address = NULL;
            const struct aws_host_address *first_available = NULL;

            /* Prefer IPv4 when available, otherwise fall back to the first usable entry */
            for (size_t i = 0; i < address_count; ++i) {
                const struct aws_host_address *current = NULL;
                aws_array_list_get_at_ptr(host_addresses, (void **)&current, i);
                if (!current || !current->address) {
                    continue;
                }
                if (!first_available) {
                    first_available = current;
                }
                if (current->record_type == AWS_ADDRESS_RECORD_TYPE_A) {
                    chosen_address = current;
                    break;
                }
            }

            if (!chosen_address) {
                chosen_address = first_available;
            }

            if (!chosen_address || !chosen_address->address) {
                error_code = AWS_IO_DNS_INVALID_NAME;
                socks5_bootstrap->resolution_error_code = error_code;
            } else {
                struct aws_string *resolved_ip =
                    aws_string_new_from_string(socks5_bootstrap->allocator, chosen_address->address);
                if (!resolved_ip) {
                    error_code = aws_last_error();
                    socks5_bootstrap->resolution_error_code = error_code;
                } else {
                    aws_string_destroy(socks5_bootstrap->endpoint_host);
                    socks5_bootstrap->endpoint_host = resolved_ip;
                    socks5_bootstrap->endpoint_address_type =
                        chosen_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA
                            ? AWS_SOCKS5_ATYP_IPV6
                            : AWS_SOCKS5_ATYP_IPV4;
                    socks5_bootstrap->endpoint_ready = true;
                    socks5_bootstrap->resolution_error_code = AWS_ERROR_SUCCESS;
                    error_code = AWS_ERROR_SUCCESS;

                    AWS_LOGF_DEBUG(
                        AWS_LS_IO_SOCKS5,
                        "id=%p: Resolved endpoint '%s' to %s",
                        (void *)socks5_bootstrap,
                        socks5_bootstrap->original_endpoint_host
                            ? aws_string_c_str(socks5_bootstrap->original_endpoint_host)
                            : "",
                        aws_string_c_str(resolved_ip));
                }
            }
        }
    }

    if (error_code != AWS_ERROR_SUCCESS) {
        socks5_bootstrap->endpoint_ready = false;
    }

    bool cleanup_now = false;

    if (error_code == AWS_ERROR_SUCCESS) {
        if (socks5_bootstrap->pending_channel && !socks5_bootstrap->resolution_task_scheduled) {
            channel_for_success = socks5_bootstrap->pending_channel;
            aws_channel_task_init(
                &socks5_bootstrap->resolution_success_task,
                s_socks5_bootstrap_resolution_success_task,
                socks5_bootstrap,
                "socks5_resolution_success");
            success_task = &socks5_bootstrap->resolution_success_task;
            socks5_bootstrap->resolution_task_scheduled = true;
        }
    } else {
        if (socks5_bootstrap->pending_channel && !socks5_bootstrap->resolution_failure_task_scheduled) {
            channel_for_failure = socks5_bootstrap->pending_channel;
            aws_channel_task_init(
                &socks5_bootstrap->resolution_failure_task,
                s_socks5_bootstrap_resolution_failure_task,
                socks5_bootstrap,
                "socks5_resolution_failure");
            failure_task = &socks5_bootstrap->resolution_failure_task;
            socks5_bootstrap->resolution_failure_task_scheduled = true;
        }
    }

    if (socks5_bootstrap->cleanup_pending && !socks5_bootstrap->resolution_in_progress &&
        success_task == NULL && failure_task == NULL) {
        /* shutdown requested earlier; resolver is the last owner so finish cleanup now */
        cleanup_now = true;
        socks5_bootstrap->cleanup_pending = false;
    }

    aws_mutex_unlock(&socks5_bootstrap->lock);

    if (success_task && channel_for_success) {
        aws_channel_schedule_task_now(channel_for_success, success_task);
    }

    if (failure_task && channel_for_failure) {
        aws_channel_schedule_task_now(channel_for_failure, failure_task);
    }

    if (cleanup_now) {
        s_cleanup_bootstrap(socks5_bootstrap);
    }
}

int aws_socks5_client_bootstrap_new_socket_channel(struct aws_socket_channel_bootstrap_options *options) {
    AWS_PRECONDITION(options);
    AWS_FATAL_ASSERT(
        s_socks5_system_vtable && s_socks5_system_vtable->aws_client_bootstrap_new_socket_channel &&
        "socks5 system vtable must provide aws_client_bootstrap_new_socket_channel");
    return s_socks5_system_vtable->aws_client_bootstrap_new_socket_channel(options);
}

static int s_socks5_bootstrap_create_proxy_options(
    struct aws_socks5_bootstrap *socks5_bootstrap,
    struct aws_allocator *allocator,
    const struct aws_socks5_proxy_options *socks5_proxy_options,
    struct aws_socket_channel_bootstrap_options *channel_options) 
{
    if (!socks5_bootstrap) {
        return AWS_OP_ERR;
    }

    socks5_bootstrap->allocator = allocator;
    socks5_bootstrap->bootstrap = channel_options->bootstrap;
    socks5_bootstrap->setup_callback = channel_options->setup_callback;
    socks5_bootstrap->shutdown_callback = channel_options->shutdown_callback;
    socks5_bootstrap->user_data = channel_options->user_data;

    if (s_socks5_bootstrap_set_socks5_proxy_options(
            socks5_bootstrap,
            allocator,
            socks5_proxy_options,
            channel_options->host_name,
            channel_options->port)) {
        s_release_bootstrap_resources(socks5_bootstrap);
        return AWS_OP_ERR;
    }

    if (s_socks5_bootstrap_set_tls_options(socks5_bootstrap, allocator, channel_options->tls_options)) {
        s_release_bootstrap_resources(socks5_bootstrap);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_client_bootstrap_new_socket_channel_with_socks5(
    struct aws_allocator *allocator,
    struct aws_socket_channel_bootstrap_options *channel_options,
    const struct aws_socks5_proxy_options *socks5_proxy_options) 
{
    if (!allocator || !socks5_proxy_options || !channel_options) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_socks5_bootstrap *socks5_bootstrap = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_bootstrap));
    if (!socks5_bootstrap) {
        return AWS_OP_ERR;
    }

    if (aws_mutex_init(&socks5_bootstrap->lock) != AWS_OP_SUCCESS) {
        aws_mem_release(allocator, socks5_bootstrap);
        return AWS_OP_ERR;
    }

    if (s_socks5_bootstrap_create_proxy_options(
            socks5_bootstrap, allocator, socks5_proxy_options, channel_options)) {
        s_cleanup_bootstrap(socks5_bootstrap);
        return AWS_OP_ERR;
    }

    if (s_socks5_bootstrap_start_endpoint_resolution(socks5_bootstrap, channel_options)) {
        s_cleanup_bootstrap(socks5_bootstrap);
        return AWS_OP_ERR;
    }

    // Update channel options for socks5 socket
    s_socks5_bootstrap_create_channel_options(socks5_bootstrap, channel_options);

    AWS_FATAL_ASSERT(
        s_socks5_system_vtable && s_socks5_system_vtable->aws_client_bootstrap_new_socket_channel &&
        "socks5 system vtable must provide aws_client_bootstrap_new_socket_channel");

    int result = s_socks5_system_vtable->aws_client_bootstrap_new_socket_channel(channel_options);
    if (result == AWS_OP_ERR) {
        s_cleanup_bootstrap(socks5_bootstrap);
    }

    return result;
}

/* Start the SOCKS5 handshake process manually */
int aws_socks5_channel_handler_start_handshake(struct aws_channel_handler *handler) {
    AWS_ASSERT(handler);
    
    if (!handler) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    if (handler->vtable != &s_socks5_handler_vtable) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    struct aws_socks5_channel_handler *socks5_handler = handler->impl;
    if (!socks5_handler) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Check if handler has slot */
    if (!handler->slot) {
        /* Don't fail here - the handshake will be started when the slot is set */
        return AWS_OP_SUCCESS;
    }
        
    /* Make sure the slot has a channel */
    if (handler->slot->channel == NULL) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    
    /* Don't start handshake if we're not in INIT state */
    if (socks5_handler->channel_state != AWS_SOCKS5_CHANNEL_STATE_INIT) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Cannot start handshake in state %d",
            (void *)handler,
            socks5_handler->channel_state);
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    
    /* Make sure processing incoming data is enabled */
    socks5_handler->process_incoming_data = true;
    
    /* Start the SOCKS5 connection process */
    return s_start_socks5_handshake(handler, handler->slot);
}

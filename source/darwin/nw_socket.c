/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/private/socket_impl.h>
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/logging.h>
#include <aws/io/private/event_loop_impl.h>

#include <Network/Network.h>
#include <aws/io/private/tls_channel_handler_shared.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "./dispatch_queue_event_loop_private.h"

static int s_determine_socket_error(int error) {
    switch (error) {
        case ECONNREFUSED:
            return AWS_IO_SOCKET_CONNECTION_REFUSED;
        case ETIMEDOUT:
            return AWS_IO_SOCKET_TIMEOUT;
        case EHOSTUNREACH:
        case ENETUNREACH:
            return AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
        case EADDRNOTAVAIL:
            return AWS_IO_SOCKET_INVALID_ADDRESS;
        case ENETDOWN:
            return AWS_IO_SOCKET_NETWORK_DOWN;
        case ECONNABORTED:
            return AWS_IO_SOCKET_CONNECT_ABORTED;
        case EADDRINUSE:
            return AWS_IO_SOCKET_ADDRESS_IN_USE;
        case ENOBUFS:
        case ENOMEM:
            return AWS_ERROR_OOM;
        case EAGAIN:
            return AWS_IO_READ_WOULD_BLOCK;
        case EMFILE:
        case ENFILE:
            return AWS_ERROR_MAX_FDS_EXCEEDED;
        case ENOENT:
        case EINVAL:
            return AWS_ERROR_FILE_INVALID_PATH;
        case EAFNOSUPPORT:
            return AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY;
        case EACCES:
            return AWS_ERROR_NO_PERMISSION;
        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static inline int s_convert_pton_error(int pton_code) {
    if (pton_code == 0) {
        return AWS_IO_SOCKET_INVALID_ADDRESS;
    }

    return s_determine_socket_error(errno);
}

/* other than CONNECTED_READ | CONNECTED_WRITE
 * a socket is only in one of these states at a time. */
enum nw_socket_state {
    INIT = 0x001,
    CONNECTING = 0x002,
    CONNECTED_READ = 0x004,
    CONNECTED_WRITE = 0x008,
    BOUND = 0x010,
    LISTENING = 0x020,
    STOPPED = 0x040, // Stop the io events, while we could restart it later
    ERROR = 0x080,
    CLOSING = 0X100, // Only set when aws_socket_close() is called.
    CLOSED = 0x200,
};

struct nw_listener_connection_args {
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    nw_connection_t new_connection;
    void *user_data;
};

struct nw_socket_timeout_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    bool cancelled;
};

struct nw_socket_scheduled_task_args {
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    dispatch_data_t data;
};

struct nw_socket_written_args {
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    aws_socket_on_write_completed_fn *written_fn;
    void *user_data;
    size_t bytes_written;
};

struct nw_socket_cancel_task_args {
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    struct aws_task *task_to_cancel;
};

struct nw_socket {
    struct aws_allocator *allocator;
    /* The external ref count that keeps the nw_socket alive. The ref_count initalized on aws_socket_init() and
     * decreased on aws_socket_clean_up() called. The internal_ref_count will also keep a reference of the ref_count so
     * that the nw_socket would alive until all system callbacks and tasks are handled.*/
    struct aws_ref_count ref_count;
    /* The internal ref count is used to track any in-flight socket operations. It would be init on socket init, and
     * acquired on aws_socket_connect()/aws_socket_listen() called. The reference will be decreased on
     * nw_connection/listener_state_changed_handler is invoked with a "nw_connection/listener_state_cancelled" state.
     * Besides this, each network framework system call or each scheduled task in event loop would also acquire an
     * internal reference, and release when the callback invoked or the task executed. */
    struct aws_ref_count internal_ref_count;
    int last_error;

    /* Apple's native structs for connection and listener. */
    nw_connection_t nw_connection;
    nw_listener_t nw_listener;
    nw_parameters_t socket_options_to_params;
    /* The socket would be either setup as nw_connection or nw_listener. If `is_listener` set to true, nw_listener will
     * be used, otherwise nw_connection will be used. */
    bool is_listener;

    /* The liked list of `read_queue_node`. The read queue to store read data from io events. aws_socket_read() function
     * would read data from the queue. */
    struct aws_linked_list read_queue;
    /* As we have to wait for read system call if there is already do a read system call, we wait until we proceed the
     * data read back from this one before we do another read call. */
    bool read_queued;

    /*
     * nw_socket is ref counted. It is possible that the aws_socket object is released while nw_socket is still alive
     * and processing events. We keep the callbacks and parameters on nw_socket to avoid bad access after the aws_socket
     * is released.
     */
    aws_socket_on_readable_fn *on_readable;
    void *on_readable_user_data;
    aws_socket_on_connection_result_fn *on_connection_result_fn;
    void *connect_accept_user_data;
    aws_socket_on_shutdown_complete_fn *on_socket_close_complete_fn;
    void *close_user_data;
    aws_socket_on_shutdown_complete_fn *on_socket_cleanup_complete_fn;
    void *cleanup_user_data;

    /* nw_socket had to be assigned to an event loop to process events. The nw_socket will acquire a reference of the
     * event_loop's base event group to kept the event loop alive.
     *
     *  For client socket (nw_connection): setup on aws_socket_connect()
     *  For listener (nw_listener) : setup on aws_socket_start_accept()
     *  For incoming socket / server socket (nw_connection accepted on a listener): setup by calling
     * aws_socket_assign_event_loop()
     */
    struct aws_event_loop *event_loop;

    /* Indicate the connection result is updated. Set to true if
     *      1. nw_connection returned with state=`nw_connection_state_ready`, indicating the connection succeed
     *      2. nw_connection returned with state=`nw_connection_state_failed`, indicating the connection failed
     *      3. directly set to true for the incoming socket, as the incoming socket is already connected
     */
    bool connection_setup;

    /* Timeout task that is created on aws_socket_connect(). The task will be flagged to be canceled if the connection
     * succeed or failed. */
    struct nw_socket_timeout_args *timeout_args;

    /* Synced data. The nw_socket kept a point to base_socket and event loop. Protect them with lock as we might access
     * them from system callback which is on a unpredictable thread.*/
    struct {
        struct aws_mutex lock;
        struct aws_socket *base_socket;
    } synced_data;

    /* The nw_socket_state. aws_socket also has a field `state` which should be represent the same parameter,
    however, as
     * it is possible that the aws_socket object is released while nw_socket is still alive, we will use
     * nw_socket->state instead of socket->state to verify the socket_state. */
    struct {
        int state;
        struct aws_mutex lock;
    } synced_state;
};

struct socket_address {
    union sock_addr_types {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
        struct sockaddr_un un_addr;
    } sock_addr_types;
};

static size_t KB_16 = 16 * 1024;

static void *nw_socket_acquire_internal_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_acquire(&nw_socket->internal_ref_count);
}

static size_t nw_socket_release_internal_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_release(&nw_socket->internal_ref_count);
}

static int s_lock_socket_state(struct nw_socket *nw_socket) {
    return aws_mutex_lock(&nw_socket->synced_state.lock);
}

static int s_unlock_socket_state(struct nw_socket *nw_socket) {
    return aws_mutex_unlock(&nw_socket->synced_state.lock);
}

static bool s_validate_event_loop(struct aws_event_loop *event_loop) {
    return event_loop && event_loop->vtable && event_loop->impl_data;
}

static void s_set_event_loop(struct aws_socket *aws_socket, struct aws_event_loop *event_loop) {
    aws_socket->event_loop = event_loop;
    struct nw_socket *nw_socket = aws_socket->impl;
    // Never re-assign an event loop
    AWS_ASSERT(nw_socket->event_loop == NULL);
    nw_socket->event_loop = event_loop;

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: s_set_event_loop: socket acquire event loop group.", (void *)nw_socket);
    aws_event_loop_group_acquire(get_base_event_loop_group(event_loop));
}

static void s_release_event_loop(struct nw_socket *nw_socket) {
    if (nw_socket->event_loop == NULL) {
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: s_release_event_loop: socket has not event loop.", (void *)nw_socket);
        return;
    }
    aws_event_loop_group_release(get_base_event_loop_group(nw_socket->event_loop));
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p: s_release_event_loop: socket release event loop group.", (void *)nw_socket);
    nw_socket->event_loop = NULL;
}

static inline void s_set_socket_state(struct nw_socket *nw_socket, struct aws_socket *socket, int state) {
    s_lock_socket_state(nw_socket);
    // The state can only go increasing, except for LISTENING and STOPPED. They can switch between each other.
    if (nw_socket->synced_state.state < state || (state == LISTENING && nw_socket->synced_state.state == STOPPED)) {
        nw_socket->synced_state.state = state;
        if (socket) {
            socket->state = state;
        }
    }
    s_unlock_socket_state(nw_socket);
}

static int s_setup_socket_params(struct nw_socket *nw_socket, const struct aws_socket_options *options) {
    if (options->type == AWS_SOCKET_STREAM) {
        /* if TCP, setup all the tcp options */
        if (options->domain == AWS_SOCKET_IPV4 || options->domain == AWS_SOCKET_IPV6) {
            // DEBUG WIP NW_PARAMETERS_DISABLE_PROTOCOL will need to be changed to use MTLS With SecItem
            nw_socket->socket_options_to_params =
                nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, ^(nw_protocol_options_t nw_options) {
                  if (options->connect_timeout_ms) {
                      /* this value gets set in seconds. */
                      nw_tcp_options_set_connection_timeout(
                          nw_options, options->connect_timeout_ms / AWS_TIMESTAMP_MILLIS);
                  }

                  // Only change default keepalive values if keepalive is true and both interval and timeout
                  // are not zero.
                  if (options->keepalive && options->keep_alive_interval_sec != 0 &&
                      options->keep_alive_timeout_sec != 0) {
                      nw_tcp_options_set_enable_keepalive(nw_options, options->keepalive);
                      nw_tcp_options_set_keepalive_idle_time(nw_options, options->keep_alive_timeout_sec);
                      nw_tcp_options_set_keepalive_interval(nw_options, options->keep_alive_interval_sec);
                  }

                  if (options->keep_alive_max_failed_probes) {
                      nw_tcp_options_set_keepalive_count(nw_options, options->keep_alive_max_failed_probes);
                  }

                  if (g_aws_channel_max_fragment_size < KB_16) {
                      nw_tcp_options_set_maximum_segment_size(nw_options, g_aws_channel_max_fragment_size);
                  }
                });
        } else if (options->domain == AWS_SOCKET_LOCAL) {
            nw_socket->socket_options_to_params =
                nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        }
    } else if (options->type == AWS_SOCKET_DGRAM) {
        nw_socket->socket_options_to_params =
            nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    }

    if (!nw_socket->socket_options_to_params) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p options=%p: failed to create nw_parameters_t for nw_socket.",
            (void *)nw_socket,
            (void *)options);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    nw_parameters_set_reuse_local_address(nw_socket->socket_options_to_params, true);

    return AWS_OP_SUCCESS;
}

static void s_socket_cleanup_fn(struct aws_socket *socket);
static int s_socket_connect_fn(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data);
static int s_socket_bind_fn(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
static int s_socket_listen_fn(struct aws_socket *socket, int backlog_size);
static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data);
static int s_socket_stop_accept_fn(struct aws_socket *socket);
static int s_socket_close_fn(struct aws_socket *socket);
static int s_socket_shutdown_dir_fn(struct aws_socket *socket, enum aws_channel_direction dir);
static int s_socket_set_options_fn(struct aws_socket *socket, const struct aws_socket_options *options);
static int s_socket_assign_to_event_loop_fn(struct aws_socket *socket, struct aws_event_loop *event_loop);
static int s_socket_subscribe_to_readable_events_fn(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data);
static int s_socket_read_fn(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_socket_write_fn(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data);
static int s_socket_get_error_fn(struct aws_socket *socket);
static bool s_socket_is_open_fn(struct aws_socket *socket);
static int s_set_close_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data);
static int s_set_cleanup_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data);

static struct aws_socket_vtable s_vtable = {
    .socket_cleanup_fn = s_socket_cleanup_fn,
    .socket_connect_fn = s_socket_connect_fn,
    .socket_bind_fn = s_socket_bind_fn,
    .socket_listen_fn = s_socket_listen_fn,
    .socket_start_accept_fn = s_socket_start_accept_fn,
    .socket_stop_accept_fn = s_socket_stop_accept_fn,
    .socket_close_fn = s_socket_close_fn,
    .socket_shutdown_dir_fn = s_socket_shutdown_dir_fn,
    .socket_set_options_fn = s_socket_set_options_fn,
    .socket_assign_to_event_loop_fn = s_socket_assign_to_event_loop_fn,
    .socket_subscribe_to_readable_events_fn = s_socket_subscribe_to_readable_events_fn,
    .socket_read_fn = s_socket_read_fn,
    .socket_write_fn = s_socket_write_fn,
    .socket_get_error_fn = s_socket_get_error_fn,
    .socket_is_open_fn = s_socket_is_open_fn,
    .socket_set_close_callback = s_set_close_callback,
    .socket_set_cleanup_callback = s_set_cleanup_callback,
};

static void s_schedule_next_read(struct nw_socket *socket);

static void s_socket_cleanup_fn(struct aws_socket *socket) {
    if (!socket->impl) {
        /* protect from double clean */
        return;
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p nw_socket=%p: is cleanup...", (void *)socket, (void *)socket->impl);
    if (aws_socket_is_open(socket)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p nw_socket=%p: is still open, closing...", (void *)socket, (void *)socket->impl);
        aws_socket_close(socket);
    }

    struct nw_socket *nw_socket = socket->impl;

    if (s_validate_event_loop(socket->event_loop) && !aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        aws_mutex_lock(&nw_socket->synced_data.lock);
        nw_socket->synced_data.base_socket = NULL;
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    } else {
        // If we are already on event loop or event loop is unavailable, we should already acquire the lock for base
        // socket access
        nw_socket->synced_data.base_socket = NULL;
    }

    aws_ref_count_release(&nw_socket->ref_count);
    socket->impl = NULL;
    AWS_ZERO_STRUCT(*socket);
}

struct read_queue_node {
    struct aws_allocator *allocator;
    dispatch_data_t received_data;
    struct aws_linked_list_node node;
    size_t current_offset;
};

static void s_clean_up_read_queue_node(struct read_queue_node *node) {
    /* releases reference count on dispatch_data_t that was increased during creation of read_queue_node */
    dispatch_release(node->received_data);
    aws_mem_release(node->allocator, node);
}

struct socket_close_complete_args {
    struct aws_allocator *allocator;
    aws_socket_on_shutdown_complete_fn *shutdown_complete_fn;
    void *user_data;
    struct nw_socket *nw_socket;
};

static void s_close_complete_callback(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    struct socket_close_complete_args *task_arg = arg;
    struct aws_allocator *allocator = task_arg->allocator;
    if (task_arg->shutdown_complete_fn) {
        task_arg->shutdown_complete_fn(task_arg->user_data);
    }
    aws_ref_count_release(&task_arg->nw_socket->ref_count);
    aws_mem_release(allocator, task_arg);
    aws_mem_release(allocator, task);
}

static void s_socket_impl_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p : start s_socket_impl_destroy", (void *)sock_ptr);
    /* In case we have leftovers from the read queue, clean them up. */
    while (!aws_linked_list_empty(&nw_socket->read_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&nw_socket->read_queue);
        struct read_queue_node *read_queue_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);
        s_clean_up_read_queue_node(read_queue_node);
    }

    /* Network Framework cleanup */
    if (nw_socket->socket_options_to_params) {
        nw_release(nw_socket->socket_options_to_params);
        nw_socket->socket_options_to_params = NULL;
    }

    aws_socket_on_shutdown_complete_fn *on_cleanup_complete = nw_socket->on_socket_cleanup_complete_fn;
    void *cleanup_user_data = nw_socket->cleanup_user_data;

    aws_mutex_clean_up(&nw_socket->synced_data.lock);
    aws_mutex_clean_up(&nw_socket->synced_state.lock);
    aws_mem_release(nw_socket->allocator, nw_socket);

    nw_socket = NULL;

    if (on_cleanup_complete) {
        on_cleanup_complete(cleanup_user_data);
    }
}

static void s_socket_internal_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p : start s_socket_internal_destroy", (void *)sock_ptr);

    aws_mutex_lock(&nw_socket->synced_data.lock);
    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct aws_task *task = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct aws_task));
        struct socket_close_complete_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct socket_close_complete_args));

        args->shutdown_complete_fn = nw_socket->on_socket_close_complete_fn;
        args->user_data = nw_socket->close_user_data;
        args->allocator = nw_socket->allocator;
        args->nw_socket = nw_socket;
        task->arg = args;
        aws_ref_count_acquire(&nw_socket->ref_count);
        aws_task_init(task, s_close_complete_callback, args, "SocketShutdownCompleteTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
    } else {
        // If we are not on the event loop
        if (nw_socket->on_socket_close_complete_fn) {
            nw_socket->on_socket_close_complete_fn(nw_socket->close_user_data);
        }
    }
    s_release_event_loop(nw_socket);
    aws_mutex_unlock(&nw_socket->synced_data.lock);
    aws_ref_count_release(&nw_socket->ref_count);
}

int aws_socket_init_apple_nw_socket(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    AWS_ASSERT(options);
    AWS_ZERO_STRUCT(*socket);

    // Network Interface is not supported with Apple Network Framework yet
    size_t network_interface_length = 0;
    if (aws_secure_strlen(options->network_interface_name, AWS_NETWORK_INTERFACE_NAME_MAX, &network_interface_length)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p fd=%d: network_interface_name max length must be %d length and NULL terminated",
            (void *)socket,
            socket->io_handle.data.fd,
            AWS_NETWORK_INTERFACE_NAME_MAX);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }
    if (network_interface_length != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p fd=%d: network_interface_name is not supported on this platform.",
            (void *)socket,
            socket->io_handle.data.fd);
        return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
    }

    struct nw_socket *nw_socket = aws_mem_calloc(alloc, 1, sizeof(struct nw_socket));
    nw_socket->allocator = alloc;

    socket->allocator = alloc;
    socket->options = *options;
    socket->impl = nw_socket;
    socket->vtable = &s_vtable;

    aws_mutex_init(&nw_socket->synced_data.lock);
    aws_mutex_init(&nw_socket->synced_state.lock);

    aws_mutex_lock(&nw_socket->synced_data.lock);
    nw_socket->synced_data.base_socket = socket;
    aws_mutex_unlock(&nw_socket->synced_data.lock);

    s_set_socket_state(nw_socket, socket, INIT);

    if (s_setup_socket_params(nw_socket, options)) {
        aws_mem_release(alloc, nw_socket);
        return AWS_OP_ERR;
    }
    aws_ref_count_init(&nw_socket->ref_count, nw_socket, s_socket_impl_destroy);
    aws_ref_count_init(&nw_socket->internal_ref_count, nw_socket, s_socket_internal_destroy);
    aws_ref_count_acquire(&nw_socket->ref_count);
    aws_linked_list_init(&nw_socket->read_queue);

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p fd=%d: socket created.", (void *)nw_socket, socket->io_handle.data.fd);

    return AWS_OP_SUCCESS;
}

static void s_client_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_connection_set_queue(handle->data.handle, queue);
}

static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    (void)task;
    (void)status;

    struct nw_socket_timeout_args *timeout_args = args;
    struct nw_socket *nw_socket = timeout_args->nw_socket;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "task_id=%p: timeout task triggered, evaluating timeouts.", (void *)task);

    aws_mutex_lock(&nw_socket->synced_data.lock);
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    /* successful connection will have nulled out timeout_args->socket */
    if (!timeout_args->cancelled && socket) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: timed out, shutting down.",
            (void *)socket,
            (void *)nw_socket->nw_connection);

        int error_code = AWS_IO_SOCKET_TIMEOUT;

        if (status != AWS_TASK_STATUS_RUN_READY) {
            error_code = AWS_IO_EVENT_LOOP_SHUTDOWN;
            // nw_socket->event_loop = NULL;
        }
        aws_raise_error(error_code);
        // Must set timeout_args to NULL to avoid double cancel. Clean up the timeout task
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
        nw_socket->timeout_args = NULL;
        aws_socket_close(socket);
        nw_socket->on_connection_result_fn(socket, error_code, nw_socket->connect_accept_user_data);
    } else { // else we simply clean up the timeout args
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
        nw_socket->timeout_args = NULL;
    }

    aws_mutex_unlock(&nw_socket->synced_data.lock);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_handle_socket_timeout   %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(nw_socket);
    // No need to release task, as task lives on timeout_args on nw_socket.
}

static void s_process_readable_task(struct aws_task *task, void *arg, enum aws_task_status status) {

    (void)status;
    struct nw_socket_scheduled_task_args *readable_args = arg;
    struct nw_socket *nw_socket = readable_args->nw_socket;
    bool data_processed = false;

    if (status != AWS_TASK_STATUS_CANCELED) {

        // If data is valid, push it in read_queue. The read_queue should be only accessed in event loop, as the
        // task is scheduled in event loop, it is fine to directly access it.
        if (readable_args->data) {
            struct read_queue_node *node = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct read_queue_node));
            node->allocator = nw_socket->allocator;
            node->received_data = readable_args->data;
            aws_linked_list_push_back(&nw_socket->read_queue, &node->node);
            data_processed = true;
        }

        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        if (socket && readable_args->error_code == AWS_IO_SOCKET_CLOSED) {
            aws_socket_close(socket);
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);

        if (nw_socket->on_readable) {
            nw_socket->on_readable(socket, readable_args->error_code, nw_socket->on_readable_user_data);
        }
    }

    // If the task is cancelled and the data is not handled, release it.
    if (!data_processed && readable_args->data) {
        dispatch_release(readable_args->data);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_readable_task  %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(nw_socket);

    aws_mem_release(readable_args->allocator, task);
    aws_mem_release(readable_args->allocator, readable_args);
}

static void s_schedule_on_readable(struct nw_socket *nw_socket, int error_code, dispatch_data_t data) {

    aws_mutex_lock(&nw_socket->synced_data.lock);
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    if (socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));

        struct nw_socket_scheduled_task_args *args =
            aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;

        if (data) {
            dispatch_retain(data);
            args->data = data;
        }
        nw_socket_acquire_internal_ref(nw_socket);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: s_process_readable_task", (void *)nw_socket);
        aws_task_init(task, s_process_readable_task, args, "readableTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
    }
    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static void s_process_connection_result_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;

    struct nw_socket_scheduled_task_args *task_args = arg;
    struct nw_socket *nw_socket = task_args->nw_socket;

    if (status != AWS_TASK_STATUS_CANCELED) {
        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        if (socket && nw_socket->on_connection_result_fn)
            nw_socket->on_connection_result_fn(socket, task_args->error_code, nw_socket->connect_accept_user_data);
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_connection_result_task  %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(nw_socket);

    aws_mem_release(task_args->allocator, task);
    aws_mem_release(task_args->allocator, task_args);
}

static void s_schedule_on_connection_result(struct nw_socket *nw_socket, int error_code) {

    aws_mutex_lock(&nw_socket->synced_data.lock);
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    if (socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));

        struct nw_socket_scheduled_task_args *args =
            aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

        args->nw_socket = nw_socket;
        args->allocator = socket->allocator;
        args->error_code = error_code;
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_acquire_internal_ref: s_process_connection_result_task",
            (void *)nw_socket);
        aws_task_init(task, s_process_connection_result_task, args, "connectionSuccessTask");
        nw_socket_acquire_internal_ref(nw_socket);
        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
    }

    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

struct connection_state_change_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct nw_socket *nw_socket;
    nw_connection_t nw_connection;
    nw_connection_state_t state;
    int error;
};

static void s_process_connection_state_changed_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;

    struct connection_state_change_args *connection_args = args;

    struct nw_socket *nw_socket = connection_args->nw_socket;
    nw_connection_t nw_connection = connection_args->nw_connection;
    nw_connection_state_t state = connection_args->state;

    if (state == nw_connection_state_cancelled) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection on port cancelled ",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection);
        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        s_set_socket_state(nw_socket, socket, CLOSED);
        aws_mutex_unlock(&nw_socket->synced_data.lock);

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_release_internal_ref: connection canceled  %lu",
            (void *)nw_socket,
            aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
        nw_socket_release_internal_ref(nw_socket);

    } else if (state == nw_connection_state_ready) { /* we're connected! */
        AWS_LOGF_INFO(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection success",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection);
        nw_path_t path = nw_connection_copy_current_path(nw_connection);
        nw_endpoint_t local_endpoint = nw_path_copy_effective_local_endpoint(path);
        nw_release(path);
        const char *hostname = nw_endpoint_get_hostname(local_endpoint);
        uint16_t port = nw_endpoint_get_port(local_endpoint);

        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        if (socket) {
            if (hostname != NULL) {
                size_t hostname_len = strlen(hostname);
                size_t buffer_size = AWS_ARRAY_SIZE(socket->local_endpoint.address);
                size_t to_copy = aws_min_size(hostname_len, buffer_size);
                memcpy(socket->local_endpoint.address, hostname, to_copy);
                socket->local_endpoint.port = port;
            }
            nw_release(local_endpoint);

            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: local endpoint %s:%d",
                (void *)socket,
                socket->io_handle.data.handle,
                socket->local_endpoint.address,
                port);
        }
        s_set_socket_state(nw_socket, socket, CONNECTED_WRITE | CONNECTED_READ);
        aws_mutex_unlock(&nw_socket->synced_data.lock);

        // Cancel the connection timeout task
        if (nw_socket->timeout_args) {
            nw_socket->timeout_args->cancelled = true;
            aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
        }

        nw_socket->connection_setup = true;
        aws_ref_count_acquire(&nw_socket->ref_count);
        s_schedule_on_connection_result(nw_socket, AWS_OP_SUCCESS);
        s_schedule_next_read(nw_socket);
        aws_ref_count_release(&nw_socket->ref_count);
    } else if (state == nw_connection_state_waiting) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket connection is waiting for a usable network before re-attempting. ErrorCode: %d.",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection,
            connection_args->error);
    } else if (state == nw_connection_state_preparing) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket connection is in the process of establishing.  ErrorCode: %d",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection,
            connection_args->error);
    } else if (state == nw_connection_state_failed) {
        /* any error, including if closed remotely in error */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection error %d",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection,
            connection_args->error);
    }

    if (connection_args->error) {
        /* any error, including if closed remotely in error */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection error %d",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection,
            connection_args->error);
        // Cancel the connection timeout task
        if (nw_socket->timeout_args) {
            nw_socket->timeout_args->cancelled = true;
            aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
        }
        int error_code = s_determine_socket_error(connection_args->error);
        nw_socket->last_error = error_code;
        aws_raise_error(error_code);
        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        s_set_socket_state(nw_socket, socket, ERROR);

        if (!nw_socket->connection_setup) {
            aws_mutex_unlock(&nw_socket->synced_data.lock);
            s_schedule_on_connection_result(nw_socket, error_code);
            nw_socket->connection_setup = true;
            aws_mutex_lock(&nw_socket->synced_data.lock);
        } else if (socket && socket->readable_fn) {
            aws_mutex_unlock(&nw_socket->synced_data.lock);
            s_schedule_on_readable(nw_socket, nw_socket->last_error, NULL);
            aws_mutex_lock(&nw_socket->synced_data.lock);
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_connection_state_change_task  %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(nw_socket);

    aws_mem_release(connection_args->allocator, task);
    aws_mem_release(connection_args->allocator, connection_args);
}

static void s_schedule_connection_state_changed_fn(
    struct aws_socket *socket,
    struct nw_socket *nw_socket,
    nw_connection_t nw_connection,
    nw_connection_state_t state,
    nw_error_t error) {

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: s_schedule_connection_state_changed_fn start...", (void *)nw_socket);

    aws_mutex_lock(&nw_socket->synced_data.lock);

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct aws_task *task = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct aws_task));

        struct connection_state_change_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct connection_state_change_args));

        args->socket = socket;
        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error = error ? nw_error_get_error_code(error) : 0;
        args->state = state;
        args->nw_connection = nw_connection;

        nw_socket_acquire_internal_ref(nw_socket);

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_acquire_internal_ref: s_process_connection_state_change_task",
            (void *)nw_socket);
        aws_task_init(task, s_process_connection_state_changed_task, args, "ConnectionStateChangedTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
        aws_mutex_unlock(&nw_socket->synced_data.lock);

    } else if (state == nw_connection_state_cancelled) {
        // If event loop is destroyed, no io events will be proceeded. Closed the internal socket.
        aws_mutex_unlock(&nw_socket->synced_data.lock);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_release_internal_ref: nw_connection_state_cancelled with no event loop  %lu",
            (void *)nw_socket,
            aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
        nw_socket_release_internal_ref(nw_socket);

    } else {
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }
}

static void s_process_listener_success_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;
    struct nw_listener_connection_args *task_args = args;
    struct aws_allocator *allocator = task_args->allocator;
    struct nw_socket *listener_nw_socket = task_args->nw_socket;

    if (status == AWS_TASK_STATUS_RUN_READY) {

        if (listener_nw_socket) {
            aws_mutex_lock(&listener_nw_socket->synced_data.lock);
            struct aws_socket *listener = listener_nw_socket->synced_data.base_socket;

            struct aws_socket *new_socket = aws_mem_calloc(allocator, 1, sizeof(struct aws_socket));
            struct aws_socket_options options = listener->options;
            int error = aws_socket_init(new_socket, allocator, &options);
            if (error) {
                aws_mem_release(allocator, new_socket);
                nw_release(task_args->new_connection);
                if (listener->accept_result_fn) {
                    listener->accept_result_fn(listener, task_args->error_code, NULL, task_args->user_data);
                }
            } else {
                new_socket->io_handle.data.handle = task_args->new_connection;

                new_socket->io_handle.set_queue = s_client_set_dispatch_queue;

                nw_endpoint_t endpoint = nw_connection_copy_endpoint(task_args->new_connection);
                const char *hostname = nw_endpoint_get_hostname(endpoint);
                uint16_t port = nw_endpoint_get_port(endpoint);

                if (hostname != NULL) {
                    size_t hostname_len = strlen(hostname);
                    size_t buffer_size = AWS_ARRAY_SIZE(new_socket->remote_endpoint.address);
                    size_t to_copy = aws_min_size(hostname_len, buffer_size);
                    memcpy(new_socket->remote_endpoint.address, hostname, to_copy);
                    new_socket->remote_endpoint.port = port;
                }
                nw_release(endpoint);

                struct nw_socket *new_nw_socket = new_socket->impl;
                new_nw_socket->nw_connection = task_args->new_connection;
                new_nw_socket->connection_setup = true;
                // Setup socket state to start read/write operations.

                s_set_socket_state(new_nw_socket, new_socket, CONNECTED_READ | CONNECTED_WRITE);

                nw_connection_set_state_changed_handler(
                    new_socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
                      s_schedule_connection_state_changed_fn(
                          new_socket, new_nw_socket, new_nw_socket->nw_connection, state, error);
                    });

                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: nw_socket_acquire_internal_ref incoming listener connect",
                    (void *)new_nw_socket,
                    listener->io_handle.data.handle);

                // released when the connection state changed to nw_connection_state_cancelled
                nw_socket_acquire_internal_ref(new_nw_socket);

                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: incoming connection",
                    (void *)listener,
                    listener->io_handle.data.handle);

                AWS_LOGF_INFO(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: connected to %s:%d, incoming handle %p",
                    (void *)listener,
                    listener->io_handle.data.handle,
                    new_socket->remote_endpoint.address,
                    new_socket->remote_endpoint.port,
                    new_socket->io_handle.data.handle);

                if (listener->accept_result_fn) {
                    listener->accept_result_fn(listener, task_args->error_code, new_socket, task_args->user_data);
                } else // The connection is not sent to user, clean it up. The nw_connection should be released in
                       // socket clean up.
                {
                    aws_socket_clean_up(new_socket);
                }
            }
            aws_mutex_unlock(&listener_nw_socket->synced_data.lock);
        }
    } else {
        // If the task is not scheduled, release the connection.
        nw_release(task_args->new_connection);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_listener_success_task %lu",
        (void *)listener_nw_socket,
        aws_atomic_load_int(&listener_nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(listener_nw_socket);

    aws_mem_release(task_args->allocator, task);
    aws_mem_release(task_args->allocator, task_args);
}

static void s_schedule_on_listener_success(
    struct nw_socket *nw_socket,
    int error_code,
    nw_connection_t new_connection,
    void *user_data) {

    aws_mutex_lock(&nw_socket->synced_data.lock);
    if (nw_socket->synced_data.base_socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct aws_task *task = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct aws_task));

        struct nw_listener_connection_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_listener_connection_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;
        args->new_connection = new_connection;
        args->user_data = user_data;

        nw_socket_acquire_internal_ref(nw_socket);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_acquire_internal_ref: s_process_listener_success_task",
            (void *)nw_socket);
        nw_retain(new_connection);

        aws_task_init(task, s_process_listener_success_task, args, "listenerSuccessTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
    }
    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static void s_process_write_task(struct aws_task *task, void *args, enum aws_task_status status) {

    struct nw_socket_written_args *task_args = args;
    struct aws_allocator *allocator = task_args->allocator;
    struct nw_socket *nw_socket = task_args->nw_socket;

    if (status != AWS_TASK_STATUS_CANCELED) {
        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        if (task_args->written_fn) {
            task_args->written_fn(socket, task_args->error_code, task_args->bytes_written, task_args->user_data);
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_write_task  %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(nw_socket);

    aws_mem_release(allocator, task);
    aws_mem_release(allocator, task_args);
}

static void s_schedule_write_fn(
    struct nw_socket *nw_socket,
    int error_code,
    size_t bytes_written,
    void *user_data,
    aws_socket_on_write_completed_fn *written_fn) {
    aws_mutex_lock(&nw_socket->synced_data.lock);
    if (s_validate_event_loop(nw_socket->event_loop)) {

        struct aws_task *task = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct aws_task));

        struct nw_socket_written_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_written_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;
        args->written_fn = written_fn;
        args->user_data = user_data;
        args->bytes_written = bytes_written;
        nw_socket_acquire_internal_ref(nw_socket);

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: s_process_write_task", (void *)nw_socket);
        aws_task_init(task, s_process_write_task, args, "writtenTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
    }

    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static int s_socket_connect_fn(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_ASSERT(event_loop);
    AWS_ASSERT(!socket->event_loop);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, socket->io_handle.data.handle);

    if (socket->event_loop) {
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    if (socket->options.type != AWS_SOCKET_DGRAM) {
        AWS_ASSERT(on_connection_result);
        s_lock_socket_state(nw_socket);
        if (nw_socket->synced_state.state != INIT) {
            aws_mutex_unlock(&nw_socket->synced_data.lock);
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
        s_unlock_socket_state(nw_socket);
    } else { /* UDP socket */
        // Apple Network Framework uses a connection based abstraction on top of the UDP layer. We should always do an
        // "connect" action here.
        s_lock_socket_state(nw_socket);
        if (nw_socket->synced_state.state != CONNECTED_READ && nw_socket->synced_state.state != INIT) {
            s_unlock_socket_state(nw_socket);
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
        s_unlock_socket_state(nw_socket);
    }

    /* fill in posix sock addr, and then let Network framework sort it out. */
    size_t address_strlen;
    if (aws_secure_strlen(remote_endpoint->address, AWS_ADDRESS_MAX_LEN, &address_strlen)) {
        return AWS_OP_ERR;
    }

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, remote_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons((uint16_t)remote_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, remote_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons((uint16_t)remote_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        strncpy(address.sock_addr_types.un_addr.sun_path, remote_endpoint->address, AWS_ADDRESS_MAX_LEN);
        address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);

    } else {
        AWS_ASSERT(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to endpoint %s:%d.",
        (void *)socket,
        socket->io_handle.data.handle,
        remote_endpoint->address,
        (int)remote_endpoint->port);

    s_set_socket_state(nw_socket, socket, CONNECTING);

    socket->remote_endpoint = *remote_endpoint;
    socket->connect_accept_user_data = user_data;
    socket->connection_result_fn = on_connection_result;

    nw_endpoint_t endpoint = nw_endpoint_create_address((struct sockaddr *)&address.sock_addr_types);

    if (!endpoint) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to create remote address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    socket->io_handle.data.handle = nw_connection_create(endpoint, nw_socket->socket_options_to_params);
    nw_socket->nw_connection = socket->io_handle.data.handle;
    nw_release(endpoint);

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection creation failed, presumably due to a bad network path.",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    socket->io_handle.set_queue = s_client_set_dispatch_queue;

    aws_event_loop_connect_handle_to_io_completion_port(event_loop, &socket->io_handle);
    s_set_event_loop(socket, event_loop);

    nw_socket->on_connection_result_fn = on_connection_result;
    nw_socket->connect_accept_user_data = user_data;

    AWS_ASSERT(socket->options.connect_timeout_ms);
    nw_socket->timeout_args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_timeout_args));

    nw_socket->timeout_args->nw_socket = nw_socket;
    nw_socket->timeout_args->allocator = socket->allocator;

    aws_task_init(
        &nw_socket->timeout_args->task,
        s_handle_socket_timeout,
        nw_socket->timeout_args,
        "NWSocketConnectionTimeoutTask");

    /* set a handler for socket state changes. This is where we find out if the connection timed out, was successful,
     * was disconnected etc .... */
    nw_connection_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
          s_schedule_connection_state_changed_fn(socket, nw_socket, nw_socket->nw_connection, state, error);
        });
    // released when the connection state changed to nw_connection_state_cancelled
    nw_socket_acquire_internal_ref(nw_socket);
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: socket_connect", (void *)nw_socket);
    nw_connection_start(socket->io_handle.data.handle);
    nw_retain(socket->io_handle.data.handle);

    /* schedule a task to run at the connect timeout interval, if this task runs before the connect
     * happens, we consider that a timeout. */

    uint64_t timeout = 0;
    aws_event_loop_current_clock_time(event_loop, &timeout);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: start connection at %llu.",
        (void *)socket,
        socket->io_handle.data.handle,
        (unsigned long long)timeout);
    timeout +=
        aws_timestamp_convert(socket->options.connect_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: scheduling timeout task for %llu.",
        (void *)socket,
        socket->io_handle.data.handle,
        (unsigned long long)timeout);
    nw_socket->timeout_args->task.timestamp = timeout;
    // Acquire a nw_socket for the timeout task
    nw_socket_acquire_internal_ref(nw_socket);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: s_handle_socket_timeout", (void *)nw_socket);
    aws_event_loop_schedule_task_future(event_loop, &nw_socket->timeout_args->task, timeout);

    return AWS_OP_SUCCESS;
}

static int s_socket_bind_fn(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    struct nw_socket *nw_socket = socket->impl;

    s_lock_socket_state(nw_socket);
    if (nw_socket->synced_state.state != INIT) {
        s_unlock_socket_state(nw_socket);
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=%p: invalid state for bind operation.", (void *)socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    s_unlock_socket_state(nw_socket);

    socket->local_endpoint = *local_endpoint;
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p: binding to %s:%d.",
        (void *)socket,
        local_endpoint->address,
        (int)local_endpoint->port);

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, local_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons((uint16_t)local_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, local_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons((uint16_t)local_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);

        strncpy(address.sock_addr_types.un_addr.sun_path, local_endpoint->address, AWS_ADDRESS_MAX_LEN);
    } else {
        AWS_ASSERT(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p: failed to parse address %s:%d.",
            (void *)socket,
            local_endpoint->address,
            (int)local_endpoint->port);
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    nw_endpoint_t endpoint = nw_endpoint_create_address((struct sockaddr *)&address.sock_addr_types);

    if (!endpoint) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    nw_parameters_set_local_endpoint(nw_socket->socket_options_to_params, endpoint);
    nw_release(endpoint);

    // Apple network framework requires connection besides bind.
    s_set_socket_state(nw_socket, socket, BOUND);

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: successfully bound", (void *)socket);

    return AWS_OP_SUCCESS;
}

static void s_listener_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_listener_set_queue(handle->data.handle, queue);
}

static int s_socket_listen_fn(struct aws_socket *socket, int backlog_size) {
    (void)backlog_size;

    struct nw_socket *nw_socket = socket->impl;

    s_lock_socket_state(nw_socket);
    if (nw_socket->synced_state.state != BOUND) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET, "id=%p: invalid state for listen operation. You must call bind first.", (void *)socket);
        s_unlock_socket_state(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    s_unlock_socket_state(nw_socket);

    socket->io_handle.data.handle = nw_listener_create(nw_socket->socket_options_to_params);
    nw_socket->nw_listener = socket->io_handle.data.handle;
    nw_retain(socket->io_handle.data.handle);
    nw_socket->is_listener = true;

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=%p:  listen failed with error code %d", (void *)socket, aws_last_error());

        s_set_socket_state(nw_socket, socket, ERROR);

        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    socket->io_handle.set_queue = s_listener_set_dispatch_queue;

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: successfully listening", (void *)socket, socket->io_handle.data.handle);

    s_set_socket_state(nw_socket, socket, LISTENING);

    return AWS_OP_SUCCESS;
}

static void s_process_set_listener_endpoint_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct nw_socket_scheduled_task_args *readable_args = arg;
    struct nw_socket *nw_socket = readable_args->nw_socket;

    aws_mutex_lock(&nw_socket->synced_data.lock);
    struct aws_socket *aws_socket = nw_socket->synced_data.base_socket;
    if (aws_socket && status == AWS_TASK_STATUS_RUN_READY) {
        if (nw_socket->is_listener) {
            aws_socket->local_endpoint.port = nw_listener_get_port(nw_socket->nw_listener);
        }
    }
    aws_mutex_unlock(&nw_socket->synced_data.lock);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_set_listener_endpoint_task  %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    nw_socket_release_internal_ref(nw_socket);

    aws_mem_release(readable_args->allocator, task);
    aws_mem_release(readable_args->allocator, arg);
}

struct listener_state_changed_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct nw_socket *nw_socket;
    nw_listener_state_t state;
    int error;
};

static void s_process_listener_state_changed_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;

    struct listener_state_changed_args *listener_state_changed_args = args;

    struct nw_socket *nw_socket = listener_state_changed_args->nw_socket;
    nw_listener_t nw_listener = nw_socket->nw_listener;
    nw_listener_state_t state = listener_state_changed_args->state;

    /* we're connected! */

    if (state == nw_listener_state_waiting) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: listener on port waiting ", (void *)nw_socket, (void *)nw_listener);

    } else if (state == nw_listener_state_failed) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: listener on port failed ", (void *)nw_socket, (void *)nw_listener);

        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection error %d",
            (void *)nw_socket,
            (void *)nw_listener,
            listener_state_changed_args->error);
    } else if (state == nw_listener_state_ready) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: listener on port ready ", (void *)nw_socket, (void *)nw_listener);

        aws_mutex_lock(&nw_socket->synced_data.lock);
        if (s_validate_event_loop(nw_socket->event_loop)) {
            struct aws_task *task = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct aws_task));

            struct nw_socket_scheduled_task_args *args =
                aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

            args->nw_socket = nw_socket;
            args->allocator = nw_socket->allocator;
            // acquire ref count for the task
            nw_socket_acquire_internal_ref(nw_socket);
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKET,
                "id=%p: nw_socket_acquire_internal_ref: s_process_set_listener_endpoint_task",
                (void *)nw_socket);

            aws_task_init(task, s_process_set_listener_endpoint_task, args, "listenerSuccessTask");
            // TODO: what if event loop is shuting down & what happened if we schedule the task here.
            aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);

    } else if (state == nw_listener_state_cancelled) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: listener on port cancelled ", (void *)nw_socket, (void *)nw_listener);

        s_set_socket_state(nw_socket, listener_state_changed_args->socket, CLOSED);

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_release_internal_ref: listener port canceled  %lu",
            (void *)nw_socket,
            aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
        nw_socket_release_internal_ref(nw_socket);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: nw_socket_release_internal_ref: s_process_listener_state_changed_task  %lu",
        (void *)nw_socket,
        aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
    // Release the internal ref for the task
    nw_socket_release_internal_ref(nw_socket);
    aws_mem_release(listener_state_changed_args->allocator, task);
    aws_mem_release(listener_state_changed_args->allocator, listener_state_changed_args);
}

static void s_schedule_listener_state_changed_fn(
    struct aws_socket *socket,
    struct nw_socket *nw_socket,
    nw_listener_state_t state,
    nw_error_t error) {

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: s_schedule_listener_state_changed_fn start...", (void *)nw_socket);

    aws_mutex_lock(&nw_socket->synced_data.lock);

    if (socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct aws_task *task = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct aws_task));

        struct listener_state_changed_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct listener_state_changed_args));

        args->socket = socket;
        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error = error ? nw_error_get_error_code(error) : 0;
        args->state = state;

        nw_socket_acquire_internal_ref(nw_socket);

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_acquire_internal_ref: s_process_listener_state_changed_task",
            (void *)nw_socket);
        aws_task_init(task, s_process_listener_state_changed_task, args, "ListenerStateChangedTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, task);
    } else if (state == nw_listener_state_cancelled) {
        // If socket and event loop is destroyed, no io events will be proceeded. Closed the internal socket.
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_release_internal_ref: nw_listener_state_cancelled with no event loop  %lu",
            (void *)nw_socket,
            aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
        nw_socket_release_internal_ref(nw_socket);
    }
    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    AWS_ASSERT(on_accept_result);
    AWS_ASSERT(accept_loop);

    if (socket->event_loop) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is already assigned to event-loop %p.",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_state(nw_socket);
    if (nw_socket->synced_state.state != LISTENING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: invalid state for start_accept operation. You must call listen first.",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_state(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    s_unlock_socket_state(nw_socket);

    aws_event_loop_connect_handle_to_io_completion_port(accept_loop, &socket->io_handle);
    socket->accept_result_fn = on_accept_result;
    socket->connect_accept_user_data = user_data;

    s_set_event_loop(socket, accept_loop);

    nw_listener_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_listener_state_t state, nw_error_t error) {
          s_schedule_listener_state_changed_fn(socket, nw_socket, state, error);
        });

    nw_listener_set_new_connection_handler(socket->io_handle.data.handle, ^(nw_connection_t connection) {
      s_schedule_on_listener_success(nw_socket, AWS_OP_SUCCESS, connection, user_data);
    });
    // this ref should be released in nw_listener_set_state_changed_handler where get state ==
    // nw_listener_state_cancelled
    nw_socket_acquire_internal_ref(nw_socket);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: s_socket_start_accept_fn", (void *)nw_socket);
    nw_listener_start(socket->io_handle.data.handle);
    return AWS_OP_SUCCESS;
}

static int s_socket_stop_accept_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_state(nw_socket);
    if (nw_socket->synced_state.state != LISTENING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is not in a listening state, can't stop_accept.",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_state(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    s_unlock_socket_state(nw_socket);

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: stopping accepting new connections",
        (void *)socket,
        socket->io_handle.data.handle);

    nw_listener_cancel(socket->io_handle.data.handle);

    s_set_socket_state(nw_socket, socket, STOPPED);

    return AWS_OP_SUCCESS;
}

// Close should always be run on event loop
static int s_socket_close_fn(struct aws_socket *socket) {

    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_state(nw_socket);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: closing state %d",
        (void *)socket,
        socket->io_handle.data.handle,
        socket->state);

    if (nw_socket->synced_state.state < CLOSING) {

        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p handle=%p: closing", (void *)socket, socket->io_handle.data.handle);

        if ((!nw_socket->is_listener && nw_socket->nw_connection != NULL) ||
            (nw_socket->is_listener && nw_socket->nw_listener != NULL)) {
            // The timeout_args only setup for connected client connections.
            if (!nw_socket->is_listener && nw_socket->timeout_args && nw_socket->connection_setup) {
                // if the timeout args is not triggered, cancel it and clean up
                nw_socket->timeout_args->cancelled = true;
                aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
            }

            if (nw_socket->is_listener && nw_socket->nw_listener != NULL) {
                nw_listener_cancel(nw_socket->nw_listener);
                nw_release(nw_socket->nw_listener);
                nw_socket->nw_listener = NULL;
            } else if (nw_socket->nw_connection != NULL) {
                nw_connection_cancel(nw_socket->nw_connection);
                nw_release(nw_socket->nw_connection);
                nw_socket->nw_connection = NULL;
            }
        }

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p: nw_socket_release_internal_ref: s_socket_close_and_release %lu",
            (void *)nw_socket,
            aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
        nw_socket_release_internal_ref(nw_socket);
    }
    s_unlock_socket_state(nw_socket);
    s_set_socket_state(nw_socket, socket, CLOSING);

    return AWS_OP_SUCCESS;
}

static int s_socket_shutdown_dir_fn(struct aws_socket *socket, enum aws_channel_direction dir) {
    (void)dir;
    // Invalid operation so far, current nw_socket does not support both dir connection
    AWS_ASSERT(true);
    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKET, "id=%p: shutdown by direction is not support for Apple network framework.", (void *)socket);
    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
}

static int s_socket_set_options_fn(struct aws_socket *socket, const struct aws_socket_options *options) {
    if (socket->options.domain != options->domain || socket->options.type != options->type) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: setting socket options to: keep-alive %d, keep idle %d, keep-alive interval %d, "
        "keep-alive "
        "probe "
        "count %d.",
        (void *)socket,
        socket->io_handle.data.handle,
        (int)options->keepalive,
        (int)options->keep_alive_timeout_sec,
        (int)options->keep_alive_interval_sec,
        (int)options->keep_alive_max_failed_probes);

    socket->options = *options;

    struct nw_socket *nw_socket = socket->impl;

    /* If nw_parameters_t has been previously set, they need to be released prior to assinging a new one */
    if (nw_socket->socket_options_to_params) {
        nw_release(nw_socket->socket_options_to_params);
        nw_socket->socket_options_to_params = NULL;
    }

    return s_setup_socket_params(nw_socket, options);
}

static int s_socket_assign_to_event_loop_fn(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    if (!socket->event_loop) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: assigning to event loop %p",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)event_loop);

        if (aws_event_loop_connect_handle_to_io_completion_port(event_loop, &socket->io_handle)) {

            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: assigning event loop %p failed",
                (void *)socket,
                socket->io_handle.data.handle,
                (void *)event_loop);
            return AWS_OP_ERR;
        }

        s_set_event_loop(socket, event_loop);
        nw_connection_start(socket->io_handle.data.handle);
        return AWS_OP_SUCCESS;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: the socket is already assigned with an event loop %p",
        (void *)socket,
        socket->io_handle.data.handle,
        (void *)event_loop);
    return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
}

/* sockets need to emulate edge-triggering. When we find that we've read all of our buffers or we preemptively know
 * we're going to want more notifications, we schedule a read. That read, upon occuring gets queued into an internal
 * buffer to then be vended upon a call to aws_socket_read() */
static void s_schedule_next_read(struct nw_socket *nw_socket) {
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    if (!socket) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read to because socket is not connected",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection);
        aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        return;
    }

    s_lock_socket_state(nw_socket);
    if (!(nw_socket->synced_state.state & CONNECTED_READ)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read to because socket is not connected",
            (void *)nw_socket,
            (void *)nw_socket->nw_connection);
        aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        s_unlock_socket_state(nw_socket);
        return;
    }
    s_unlock_socket_state(nw_socket);

    // Acquire nw_socket as we called nw_connection_receive, and the ref will be released when the handler is
    // called.
    nw_socket_acquire_internal_ref(nw_socket);
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: nw_connection_receive", (void *)nw_socket);

    /* read and let me know when you've done it. */
    nw_connection_receive(
        socket->io_handle.data.handle,
        1,
        UINT32_MAX,
        ^(dispatch_data_t data, nw_content_context_t context, bool is_complete, nw_error_t error) {
          (void)context;

          if (!error || nw_error_get_error_code(error) == 0) {
              int error = AWS_ERROR_SUCCESS;

              /* For protocols such as TCP, `is_complete` will be marked when the entire stream has be closed in the
               * reading direction. For protocols such as UDP, this will be marked when the end of a datagram has
               * been reached. */
              if (!is_complete) {
                  // schedule next read to get future I/O event
                  s_schedule_next_read(nw_socket);
              } else {
                  aws_mutex_lock(&nw_socket->synced_data.lock);
                  struct aws_socket *base_socket = nw_socket->synced_data.base_socket;

                  // If the protocol is TCP, `is_complete` means the connection is closed, raise the
                  // AWS_IO_SOCKET_CLOSED error
                  if (base_socket && base_socket->options.type != AWS_SOCKET_DGRAM) {
                      // the message is complete socket the socket
                      AWS_LOGF_TRACE(
                          AWS_LS_IO_SOCKET,
                          "id=%p handle=%p:complete hang up ",
                          (void *)nw_socket,
                          (void *)nw_socket->nw_connection);
                      aws_raise_error(AWS_IO_SOCKET_CLOSED);
                      error = AWS_IO_SOCKET_CLOSED;
                  }
                  aws_mutex_unlock(&nw_socket->synced_data.lock);
              }

              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: queued read buffer of size %d",
                  (void *)nw_socket,
                  (void *)nw_socket->nw_connection,
                  data ? (int)dispatch_data_get_size(data) : 0);

              s_schedule_on_readable(nw_socket, error, data);

          } else {
              int error_code = s_determine_socket_error(nw_error_get_error_code(error));
              aws_raise_error(error_code);

              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: error in read callback %d",
                  (void *)nw_socket,
                  (void *)nw_socket->nw_connection,
                  error_code);
              // the data might still be partially available on an error
              s_schedule_on_readable(nw_socket, error_code, data);
          }

          AWS_LOGF_DEBUG(
              AWS_LS_IO_SOCKET,
              "id=%p: nw_socket_release_internal_ref: nw_connection_receive  %lu",
              (void *)nw_socket,
              aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
          nw_socket_release_internal_ref(nw_socket);
        });
}

static int s_socket_subscribe_to_readable_events_fn(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    socket->readable_user_data = user_data;
    socket->readable_fn = on_readable;

    nw_socket->on_readable = on_readable;
    nw_socket->on_readable_user_data = user_data;

    s_schedule_next_read(nw_socket);
    return AWS_OP_SUCCESS;
}

// WARNING: This function should never lock!!!! aws_socket_read() should always called on event loop thread,
// which means we already acquire a necessary lock there.
static int s_socket_read_fn(struct aws_socket *socket, struct aws_byte_buf *read_buffer, size_t *amount_read) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_ASSERT(amount_read);

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read from a different thread than event loop %p",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    __block size_t max_to_read = read_buffer->capacity - read_buffer->len;

    /* if empty, schedule a read and return WOULD_BLOCK */
    if (aws_linked_list_empty(&nw_socket->read_queue)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read queue is empty, scheduling another read",
            (void *)socket,
            socket->io_handle.data.handle);
        s_lock_socket_state(nw_socket);
        if (!(nw_socket->synced_state.state & CONNECTED_READ)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket is not connected to read.",
                (void *)socket,
                socket->io_handle.data.handle);
            s_unlock_socket_state(nw_socket);
            return aws_raise_error(AWS_IO_SOCKET_CLOSED);
        }
        s_unlock_socket_state(nw_socket);
        if (!nw_socket->read_queued) {
            s_schedule_next_read(nw_socket);
            nw_socket->read_queued = true;
        }
        *amount_read = 0;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    nw_socket->read_queued = false;

    /* loop over the read queue, take the data and copy it over, and do so til we're either out of data
     * and need to schedule another read, or we've read entirely into the requested buffer. */
    while (!aws_linked_list_empty(&nw_socket->read_queue) && max_to_read) {
        struct aws_linked_list_node *node = aws_linked_list_front(&nw_socket->read_queue);
        struct read_queue_node *read_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);

        bool read_completed = dispatch_data_apply(
            read_node->received_data,
            (dispatch_data_applier_t) ^ (dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                (void)region;
                (void)offset;
                size_t to_copy = aws_min_size(max_to_read, size - read_node->current_offset);
                aws_byte_buf_write(read_buffer, (const uint8_t *)buffer + read_node->current_offset, to_copy);
                max_to_read -= to_copy;
                *amount_read += to_copy;
                read_node->current_offset += to_copy;
                if (read_node->current_offset == size) {
                    read_node->current_offset = 0;
                    return true;
                }
                return false;
            });

        if (read_completed) {
            aws_linked_list_remove(node);
            s_clean_up_read_queue_node(read_node);
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read of %d",
            (void *)socket,
            socket->io_handle.data.handle,
            (int)*amount_read);
    }

    /* keep replacing buffers */
    s_schedule_next_read(nw_socket);
    return AWS_OP_SUCCESS;
}

static int s_socket_write_fn(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_state(nw_socket);
    if (!(nw_socket->synced_state.state & CONNECTED_WRITE)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot write to because it is not connected",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_state(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }
    s_unlock_socket_state(nw_socket);

    AWS_ASSERT(written_fn);

    dispatch_data_t data = dispatch_data_create(cursor->ptr, cursor->len, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_socket_acquire_internal_ref(nw_socket);

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: nw_socket_acquire_internal_ref: nw_connection_send", (void *)nw_socket);

    nw_connection_send(
        socket->io_handle.data.handle, data, _nw_content_context_default_message, true, ^(nw_error_t error) {
          int error_code = !error || nw_error_get_error_code(error) == 0
                               ? AWS_OP_SUCCESS
                               : s_determine_socket_error(nw_error_get_error_code(error));

          if (error_code) {
              nw_socket->last_error = error_code;
              aws_raise_error(error_code);
              AWS_LOGF_ERROR(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: error during write %d",
                  (void *)nw_socket,
                  (void *)nw_socket->nw_connection,
                  error_code);
          }

          size_t written_size = dispatch_data_get_size(data);
          AWS_LOGF_TRACE(
              AWS_LS_IO_SOCKET,
              "id=%p handle=%p: send written size %d",
              (void *)nw_socket,
              (void *)nw_socket->nw_connection,
              (int)written_size);
          s_schedule_write_fn(nw_socket, error_code, !error_code ? written_size : 0, user_data, written_fn);

          AWS_LOGF_DEBUG(
              AWS_LS_IO_SOCKET,
              "id=%p: nw_socket_release_internal_ref: nw_connection_send  %lu",
              (void *)nw_socket,
              aws_atomic_load_int(&nw_socket->internal_ref_count.ref_count));
          nw_socket_release_internal_ref(nw_socket);
        });

    return AWS_OP_SUCCESS;
}

static int s_socket_get_error_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;

    return nw_socket->last_error;
}

static bool s_socket_is_open_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_state(nw_socket);
    bool is_open = nw_socket->synced_state.state < CLOSING;
    s_unlock_socket_state(nw_socket);
    return is_open;
}

static int s_set_close_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data) {
    struct nw_socket *nw_socket = socket->impl;
    nw_socket->close_user_data = user_data;
    nw_socket->on_socket_close_complete_fn = fn;
    return 0;
}

static int s_set_cleanup_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data) {
    struct nw_socket *nw_socket = socket->impl;
    nw_socket->cleanup_user_data = user_data;
    nw_socket->on_socket_cleanup_complete_fn = fn;
    return 0;
}

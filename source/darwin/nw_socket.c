/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/private/socket_impl.h>
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/logging.h>
#include <aws/io/private/event_loop_impl.h>

#include <Network/Network.h>
#include <aws/io/private/tls_channel_handler_shared.h>

#include <arpa/inet.h>
#include <sys/socket.h>

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

/*
 * A socket is only in one of these states at a time, except for CONNECTED_READ | CONNECTED_WRITE.
 *
 * The state can only go increasing, except for the following cases
 *      1. LISTENING and STOPPED: They can switch between each other.
 *      2. CLOSING -> ERROR: It is a valid case where socket state tries to transfer from CLOSING to ERROR, but we never
 *      actually set it to ERROR if we are already in CLOSING state. This happened in the following scenario: After we
 *      called aws_socket_close(), the socket state is set to CLOSING. And if a read callback invoked at this time, it
 *      is possible that the socket reads an ERROR and tries to set the socket state to ERROR, which makes the socket
 * state goes backwards. Though this is a valid case, we don't actually set it back to ERROR as we are shutting down the
 * socket.
 *      3. CONNECT_WRITE and CONNECT_READ: you are allow to flip the flags for these two state, while not going
 * backwards to `CONNECTING` and `INIT` state.
 */
enum aws_nw_socket_state {
    INVALID = 0x000,
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

enum aws_nw_socket_mode {
    NWSM_CONNECTION,
    NWSM_LISTENER,
};

struct nw_listener_connection_args {
    struct aws_task task;
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
    // // The `cancelled` flag set in the following situation
    // //      1. The
    // bool cancelled;
};

struct nw_socket_scheduled_task_args {
    struct aws_task task;
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    dispatch_data_t data;
    bool is_complete;
};

struct nw_socket_written_args {
    struct aws_task task;
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
    struct aws_task task;
};

struct nw_socket {
    struct aws_allocator *allocator;

    /* The `nw_socket_ref_count` that keeps the nw_socket alive. The `nw_socket_ref_count` initalized on
     * aws_socket_init() and decreased on aws_socket_clean_up() called. The `internal_ref_count` will also keep a
     * reference of the `nw_socket_ref_count` so that the nw_socket would alive until all system callbacks and tasks are
     * handled. On `nw_socket_ref_count` drops to 0, it invokes s_socket_impl_destroy, which cleanup the nw_socket
     * memory and invoke on_socket_cleanup_complete_fn.
     */
    struct aws_ref_count nw_socket_ref_count;

    /* The `internal_ref_count` is used to track any in-flight socket operations. It would be init on socket init, and
     * acquired on aws_socket_connect()/aws_socket_listen() called. The reference will be decreased on
     * nw_connection/listener_state_changed_handler is invoked with a "nw_connection/listener_state_cancelled" state.
     * Besides this, each network framework system call or each scheduled task in event loop would also acquire an
     * internal reference, and release when the callback invoked or the task executed.
     */
    struct aws_ref_count internal_ref_count;

    /* The `write_ref_count` is used to track any in-flight write operations. It would be init on aws_socket_init() and
     * dropped on aws_socket_close() call. Each aws_socket_write() function call will acquire a ref-count, and released
     * the ref-count on nw_connection_send handler is invoked.
     * When the reference is dropped to 0, it invoked the destroy function `s_nw_socket_canceled()`, and start to cancel
     * and close the Apple nw_connection/nw_listener.
     */
    struct aws_ref_count write_ref_count;

    int last_error;

    /* Apple's native structs for connection and listener. */
    union {
        nw_connection_t nw_connection;
        nw_listener_t nw_listener;
    } os_handle;
    nw_parameters_t socket_options_to_params;
    /* The socket would be either setup as nw_connection or nw_listener. */
    enum aws_nw_socket_mode mode;

    /* The linked list of `read_queue_node`. The read queue to store read data from io events. aws_socket_read()
     * function would read data from the queue. */
    struct aws_linked_list read_queue;

    /*
     * nw_socket is ref counted. It is possible that the aws_socket object is released while nw_socket is still alive
     * and processing events. We keep the callbacks and parameters on nw_socket to avoid bad access after the aws_socket
     * is released.
     */
    aws_socket_on_readable_fn *on_readable;
    void *on_readable_user_data;
    aws_socket_on_connection_result_fn *on_connection_result_fn;
    void *connect_result_user_data;
    aws_socket_on_accept_started_fn *on_accept_started_fn;
    void *listen_accept_started_user_data;
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

    /* Indicate the connection result is updated. This argument is used to cancel the timeout task. The argument should
     * be only set on socket event loop. The value will be set to true if:
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
        /* Used to avoid scheduling a duplicate read call. We would like to wait for the read call complete back before
         * we schedule another one. */
        bool read_scheduled;
    } synced_data;

    /* The aws_nw_socket_state. aws_socket also has a field `state` which should be represent the same parameter,
     * however, as it is possible that the aws_socket object is released while nw_socket is still alive, we will use
     * nw_socket->state instead of socket->state to verify the socket_state.
     */
    struct {
        enum aws_nw_socket_state state;
        struct aws_mutex lock;
    } synced_state;
};

static size_t KB_16 = 16 * 1024;

static void *s_socket_acquire_internal_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_acquire(&nw_socket->internal_ref_count);
}

static size_t s_socket_release_internal_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_release(&nw_socket->internal_ref_count);
}

static void *s_socket_acquire_write_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_acquire(&nw_socket->write_ref_count);
}

static size_t s_socket_release_write_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_release(&nw_socket->write_ref_count);
}

static int s_lock_socket_state(struct nw_socket *nw_socket) {
    return aws_mutex_lock(&nw_socket->synced_state.lock);
}

static int s_unlock_socket_state(struct nw_socket *nw_socket) {
    return aws_mutex_unlock(&nw_socket->synced_state.lock);
}

static int s_lock_socket_synced_data(struct nw_socket *nw_socket) {
    return aws_mutex_lock(&nw_socket->synced_data.lock);
}

static int s_unlock_socket_synced_data(struct nw_socket *nw_socket) {
    return aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static bool s_validate_event_loop(struct aws_event_loop *event_loop) {
    return event_loop && event_loop->vtable && event_loop->impl_data;
}

static void s_set_event_loop(struct aws_socket *aws_socket, struct aws_event_loop *event_loop) {
    aws_socket->event_loop = event_loop;
    struct nw_socket *nw_socket = aws_socket->impl;
    // Never re-assign an event loop
    AWS_FATAL_ASSERT(nw_socket->event_loop == NULL);
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

static void s_set_socket_state(struct nw_socket *nw_socket, struct aws_socket *socket, enum aws_nw_socket_state state) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p: s_set_socket_state: socket state set from %d to %d.",
        (void *)nw_socket,
        nw_socket->synced_state.state,
        state);

    s_lock_socket_state(nw_socket);
    enum aws_nw_socket_state result_state = nw_socket->synced_state.state;

    // clip the read/write bits
    enum aws_nw_socket_state read_write_bits = state & (CONNECTED_WRITE | CONNECTED_READ);
    result_state = result_state & ~CONNECTED_WRITE & ~CONNECTED_READ;

    // If the caller would like simply flip the read/write bits, set the state to invalid, as we dont have further
    // information there.
    if (~CONNECTED_WRITE == (int)state || ~CONNECTED_READ == (int)state) {
        state = INVALID;
    }

    // The state can only go increasing, except for the following cases
    //  1. LISTENING and STOPPED: They can switch between each other.
    //  2. CLOSING -> ERROR: It is a valid case where socket state tries to transfer from CLOSING to ERROR. This
    //  happened in the following scenario: After we called aws_socket_close(), the socket state is set to CLOSING. And
    //  if a read callback invoked at this time, it is possible that the socket reads an ERROR and tries to set the
    //  socket state to ERROR, which makes the socket state goes backwards. Though this is a valid case, we don't
    //  actually set it back to ERROR as we are shutting down the socket.
    //  3. CONNECT_WRITE and CONNECT_READ: you are allow to flip the flags for these two state, while not going
    //  backwards to `CONNECTING` and `INIT` state.
    if (result_state < state || (state == LISTENING && result_state == STOPPED)) {
        result_state = state;
    }

    // Set CONNECTED_WRITE and CONNECTED_READ
    result_state = result_state | read_write_bits;

    nw_socket->synced_state.state = result_state;
    if (socket) {
        socket->state = result_state;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: s_set_socket_state: socket state set to %d.",
        (void *)nw_socket,
        nw_socket->synced_state.state);

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
        } else // If domain is AWS_SOCKET_VSOCK, the domain is not supported.
        {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p options=%p: AWS_SOCKET_VSOCK is not supported on nw_socket.",
                (void *)nw_socket,
                (void *)options);
            AWS_FATAL_ASSERT(0);
            return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
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
    struct aws_socket_listener_options options);
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
        s_lock_socket_synced_data(nw_socket);
        nw_socket->synced_data.base_socket = NULL;
        s_unlock_socket_synced_data(nw_socket);
    } else {
        // If we are already on event loop or event loop is unavailable, we should already acquire the lock for base
        // socket access
        nw_socket->synced_data.base_socket = NULL;
    }

    aws_ref_count_release(&nw_socket->nw_socket_ref_count);
    socket->impl = NULL;
    AWS_ZERO_STRUCT(*socket);
}

struct read_queue_node {
    struct aws_allocator *allocator;
    dispatch_data_t received_data;
    struct aws_linked_list_node node;
    size_t region_offset;
    // If we didn't finish reading the received_data, we need to keep track of the region offset that we would
    // like to resume with
    size_t resume_region;
};

static void s_destroy_read_queue_node(struct read_queue_node *node) {
    /* releases reference count on dispatch_data_t that was increased during creation of read_queue_node */
    dispatch_release(node->received_data);
    aws_mem_release(node->allocator, node);
}

struct socket_close_complete_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    aws_socket_on_shutdown_complete_fn *shutdown_complete_fn;
    void *user_data;
    struct nw_socket *nw_socket;
};

static void s_close_complete_callback(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    (void)task;
    struct socket_close_complete_args *task_arg = arg;
    struct aws_allocator *allocator = task_arg->allocator;
    if (task_arg->shutdown_complete_fn) {
        task_arg->shutdown_complete_fn(task_arg->user_data);
    }
    aws_ref_count_release(&task_arg->nw_socket->nw_socket_ref_count);
    aws_mem_release(allocator, task_arg);
}

static void s_socket_impl_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p : start s_socket_impl_destroy", (void *)sock_ptr);
    /* In case we have leftovers from the read queue, clean them up. */
    while (!aws_linked_list_empty(&nw_socket->read_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&nw_socket->read_queue);
        struct read_queue_node *read_queue_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);
        s_destroy_read_queue_node(read_queue_node);
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

static void s_process_socket_cancel_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct nw_socket_cancel_task_args *args = arg;
    struct nw_socket *nw_socket = args->nw_socket;

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: written finished closing", (void *)nw_socket);

    if ((nw_socket->mode == NWSM_CONNECTION && nw_socket->os_handle.nw_connection != NULL) ||
        (nw_socket->mode == NWSM_LISTENER && nw_socket->os_handle.nw_listener != NULL)) {
        // The timeout_args only setup for connected client connections.
        if (nw_socket->mode == NWSM_CONNECTION && nw_socket->timeout_args && !nw_socket->connection_setup) {
            // if the connection setup is not set, the timeout task has not yet triggered, cancel it.
            aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
        }

        if (nw_socket->mode == NWSM_LISTENER) {
            nw_listener_cancel(nw_socket->os_handle.nw_listener);
            nw_release(nw_socket->os_handle.nw_listener);
            nw_socket->os_handle.nw_listener = NULL;
        } else if (nw_socket->mode == NWSM_CONNECTION) {
            nw_connection_cancel(nw_socket->os_handle.nw_connection);
            nw_release(nw_socket->os_handle.nw_connection);
            nw_socket->os_handle.nw_connection = NULL;
        }
    }

    s_socket_release_internal_ref(nw_socket);
    aws_mem_release(args->allocator, args);
}

// Cancel the socket and close the connection. The cancel should happened on the event loop.
static void s_schedule_socket_canceled(void *socket_ptr) {
    struct nw_socket *nw_socket = socket_ptr;

    s_lock_socket_state(nw_socket);
    if (nw_socket->synced_state.state >= CLOSING) {

        struct nw_socket_cancel_task_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_cancel_task_args));

        args->allocator = nw_socket->allocator;
        args->nw_socket = nw_socket;

        /* The socket cancel should happened on the event loop if possible. The event loop will not set
         * in the case where the socket is never connected/ listener is never started accept.
         */
        if (s_validate_event_loop(nw_socket->event_loop)) {

            aws_task_init(&args->task, s_process_socket_cancel_task, args, "SocketCanceledTask");

            aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
        } else {
            s_process_socket_cancel_task(&args->task, args, AWS_TASK_STATUS_RUN_READY);
        }
    }
    s_unlock_socket_state(nw_socket);
}

static void s_socket_internal_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p : start s_socket_internal_destroy", (void *)sock_ptr);

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct socket_close_complete_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct socket_close_complete_args));

        args->shutdown_complete_fn = nw_socket->on_socket_close_complete_fn;
        args->user_data = nw_socket->close_user_data;
        args->allocator = nw_socket->allocator;
        args->nw_socket = nw_socket;
        // At this point the internal ref count has been dropped to 0, and we are about to release the external ref
        // count.
        // However, we would still keep the external ref count alive until the s_close_complete_callback callback is
        // invoked. Acquire another external ref count to keep the socket alive. It will be released in
        // s_close_complete_callback.
        aws_ref_count_acquire(&nw_socket->nw_socket_ref_count);
        aws_task_init(&args->task, s_close_complete_callback, args, "SocketShutdownCompleteTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    } else {
        // If we are not on the event loop
        if (nw_socket->on_socket_close_complete_fn) {
            nw_socket->on_socket_close_complete_fn(nw_socket->close_user_data);
        }
    }
    s_release_event_loop(nw_socket);
    aws_ref_count_release(&nw_socket->nw_socket_ref_count);
}

int aws_socket_init_apple_nw_socket(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    AWS_FATAL_ASSERT(options);
    AWS_ZERO_STRUCT(*socket);

    // Network Interface is not supported with Apple Network Framework yet
    if (options->network_interface_name[0] != 0) {
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

    if (s_setup_socket_params(nw_socket, options)) {
        aws_mem_release(alloc, nw_socket);
        return AWS_OP_ERR;
    }

    aws_mutex_init(&nw_socket->synced_data.lock);
    aws_mutex_init(&nw_socket->synced_state.lock);
    nw_socket->synced_data.base_socket = socket;

    s_set_socket_state(nw_socket, socket, INIT);

    aws_ref_count_init(&nw_socket->nw_socket_ref_count, nw_socket, s_socket_impl_destroy);
    aws_ref_count_init(&nw_socket->internal_ref_count, nw_socket, s_socket_internal_destroy);
    // The internal_ref_count should keep a reference of the nw_socket_ref_count. When the internal_ref_count
    // drop to 0, it would release the nw_socket_ref_count.
    aws_ref_count_acquire(&nw_socket->nw_socket_ref_count);
    aws_ref_count_init(&nw_socket->write_ref_count, nw_socket, s_schedule_socket_canceled);

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

    s_lock_socket_synced_data(nw_socket);
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    if (!nw_socket->connection_setup && socket) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: timed out, shutting down.",
            (void *)socket,
            (void *)nw_socket->os_handle.nw_connection);

        int error_code = AWS_IO_SOCKET_TIMEOUT;

        // Must set timeout_args to NULL to avoid double cancel. Clean up the timeout task
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
        nw_socket->timeout_args = NULL;
        aws_socket_close(socket);
        nw_socket->on_connection_result_fn(socket, error_code, nw_socket->connect_result_user_data);
    } else {
        // If the socket is already setup (either succeed or failed), we have already invoked the callback to notify the
        // connection result. No need to invoke again. If the aws_socket is NULL (cleaned up by user), there is no
        // meaning to invoke the callback anymore. Simply release the memory in these two cases.
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
        nw_socket->timeout_args = NULL;
    }

    s_unlock_socket_synced_data(nw_socket);

    s_socket_release_internal_ref(nw_socket);
    // No need to release task, as task lives on timeout_args on nw_socket.
}

static void s_process_readable_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct nw_socket_scheduled_task_args *readable_args = arg;
    struct nw_socket *nw_socket = readable_args->nw_socket;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: start s_process_readable_task.",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection);

    // If data is valid, push it in read_queue. The read_queue should be only accessed in event loop, as the
    // task is scheduled in event loop, it is fine to directly access it.
    if (readable_args->data) {
        struct read_queue_node *node = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct read_queue_node));
        node->allocator = nw_socket->allocator;
        node->received_data = readable_args->data;
        aws_linked_list_push_back(&nw_socket->read_queue, &node->node);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read data is not empty, push data to read_queue",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
    }

    if (status != AWS_TASK_STATUS_CANCELED) {
        s_lock_socket_synced_data(nw_socket);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;

        if (readable_args->is_complete) {
            s_set_socket_state(nw_socket, socket, ~CONNECTED_READ);
            AWS_LOGF_TRACE(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket is complete, flip read flag",
                (void *)nw_socket,
                (void *)nw_socket->os_handle.nw_connection);
        }
        s_unlock_socket_synced_data(nw_socket);

        if (nw_socket->on_readable) {
            nw_socket->on_readable(socket, readable_args->error_code, nw_socket->on_readable_user_data);
        }
    }

    s_socket_release_internal_ref(nw_socket);

    aws_mem_release(readable_args->allocator, readable_args);
}

static void s_schedule_on_readable(
    struct nw_socket *nw_socket,
    int error_code,
    dispatch_data_t data,
    bool is_complete) {

    s_lock_socket_synced_data(nw_socket);
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    if (socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct nw_socket_scheduled_task_args *args =
            aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

        args->is_complete = is_complete;
        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;

        if (data) {
            dispatch_retain(data);
            args->data = data;
        }
        s_socket_acquire_internal_ref(nw_socket);
        aws_task_init(&args->task, s_process_readable_task, args, "readableTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    }
    s_unlock_socket_synced_data(nw_socket);
}

static void s_process_connection_result_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct nw_socket_scheduled_task_args *task_args = arg;
    struct nw_socket *nw_socket = task_args->nw_socket;

    if (status != AWS_TASK_STATUS_CANCELED) {
        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        if (socket && nw_socket->on_connection_result_fn)
            nw_socket->on_connection_result_fn(socket, task_args->error_code, nw_socket->connect_result_user_data);
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }

    s_socket_release_internal_ref(nw_socket);

    aws_mem_release(task_args->allocator, task_args);
}

static void s_schedule_on_connection_result(struct nw_socket *nw_socket, int error_code) {

    aws_mutex_lock(&nw_socket->synced_data.lock);
    struct aws_socket *socket = nw_socket->synced_data.base_socket;
    if (socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct nw_socket_scheduled_task_args *args =
            aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

        args->nw_socket = s_socket_acquire_internal_ref(nw_socket);
        args->allocator = socket->allocator;
        args->error_code = error_code;

        aws_task_init(&args->task, s_process_connection_result_task, args, "connectionSuccessTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    }

    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

struct connection_state_change_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct nw_socket *nw_socket;
    nw_connection_t nw_connection;
    nw_connection_state_t state;
    int error;
};

static void s_process_connection_state_changed_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct connection_state_change_args *connection_args = args;

    struct nw_socket *nw_socket = connection_args->nw_socket;
    nw_connection_t nw_connection = connection_args->nw_connection;
    nw_connection_state_t state = connection_args->state;

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: Apple network framework socket connection state changed to %d, nw error code : %d",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection,
        connection_args->state,
        connection_args->error);

    switch (state) {
        case nw_connection_state_cancelled: {
            aws_mutex_lock(&nw_socket->synced_data.lock);
            struct aws_socket *socket = nw_socket->synced_data.base_socket;
            s_set_socket_state(nw_socket, socket, CLOSED);
            aws_mutex_unlock(&nw_socket->synced_data.lock);

            s_socket_release_internal_ref(nw_socket);
        } break;
        case nw_connection_state_ready: {
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

                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: set local endpoint %s:%d",
                    (void *)socket,
                    socket->io_handle.data.handle,
                    socket->local_endpoint.address,
                    port);
            }
            s_set_socket_state(nw_socket, socket, CONNECTED_WRITE | CONNECTED_READ);
            aws_mutex_unlock(&nw_socket->synced_data.lock);

            nw_socket->connection_setup = true;
            // Cancel the connection timeout task
            if (nw_socket->timeout_args) {
                aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
            }
            aws_ref_count_acquire(&nw_socket->nw_socket_ref_count);
            s_schedule_on_connection_result(nw_socket, AWS_OP_SUCCESS);
            s_schedule_next_read(nw_socket);
            aws_ref_count_release(&nw_socket->nw_socket_ref_count);
        } break;
        case nw_connection_state_waiting:
        case nw_connection_state_preparing:
        case nw_connection_state_failed:
        default:
            break;
    }

    if (connection_args->error) {
        /* any error, including if closed remotely in error */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket connection get apple os error code: %d",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection,
            connection_args->error);

        int error_code = s_determine_socket_error(connection_args->error);
        nw_socket->last_error = error_code;
        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *socket = nw_socket->synced_data.base_socket;
        s_set_socket_state(nw_socket, socket, ERROR);

        if (!nw_socket->connection_setup) {
            aws_mutex_unlock(&nw_socket->synced_data.lock);
            s_schedule_on_connection_result(nw_socket, error_code);
            nw_socket->connection_setup = true;
            // Cancel the connection timeout task
            if (nw_socket->timeout_args) {
                aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
            }
            aws_mutex_lock(&nw_socket->synced_data.lock);
        } else if (socket && socket->readable_fn) {
            aws_mutex_unlock(&nw_socket->synced_data.lock);
            s_schedule_on_readable(nw_socket, nw_socket->last_error, NULL, false);
            aws_mutex_lock(&nw_socket->synced_data.lock);
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }

    s_socket_release_internal_ref(nw_socket);
    aws_mem_release(connection_args->allocator, connection_args);
}

static void s_schedule_connection_state_changed_fn(
    struct aws_socket *socket,
    struct nw_socket *nw_socket,
    nw_connection_t nw_connection,
    nw_connection_state_t state,
    nw_error_t error) {

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: s_schedule_connection_state_changed_fn start...", (void *)nw_socket);

    aws_mutex_lock(&nw_socket->synced_data.lock);

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct connection_state_change_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct connection_state_change_args));

        args->socket = socket;
        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error = error ? nw_error_get_error_code(error) : 0;
        args->state = state;
        args->nw_connection = nw_connection;

        s_socket_acquire_internal_ref(nw_socket);

        aws_task_init(&args->task, s_process_connection_state_changed_task, args, "ConnectionStateChangedTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
        aws_mutex_unlock(&nw_socket->synced_data.lock);

    } else if (state == nw_connection_state_cancelled) {
        // If event loop is destroyed, no io events will be proceeded. Closed the internal socket.
        aws_mutex_unlock(&nw_socket->synced_data.lock);
        s_socket_release_internal_ref(nw_socket);

    } else {
        aws_mutex_unlock(&nw_socket->synced_data.lock);
    }
}

static void s_process_listener_success_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;
    (void)task;
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
                new_nw_socket->os_handle.nw_connection = task_args->new_connection;
                new_nw_socket->connection_setup = true;

                // Setup socket state to start read/write operations.
                s_set_socket_state(new_nw_socket, new_socket, CONNECTED_READ | CONNECTED_WRITE);

                nw_connection_set_state_changed_handler(
                    new_socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
                      s_schedule_connection_state_changed_fn(
                          new_socket, new_nw_socket, new_nw_socket->os_handle.nw_connection, state, error);
                    });

                // released when the connection state changed to nw_connection_state_cancelled
                s_socket_acquire_internal_ref(new_nw_socket);

                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: incoming connection connected to %s:%d, the incoming handle is %p",
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
                    AWS_FATAL_ASSERT("The listener accept_result_fn should not be NULL.");
                }
            }
            aws_mutex_unlock(&listener_nw_socket->synced_data.lock);
        }
    } else {
        // If the task is not scheduled, release the connection.
        nw_release(task_args->new_connection);
    }

    s_socket_release_internal_ref(listener_nw_socket);

    aws_mem_release(task_args->allocator, task_args);
}

static void s_schedule_on_listener_success(
    struct nw_socket *nw_socket,
    int error_code,
    nw_connection_t new_connection,
    void *user_data) {

    aws_mutex_lock(&nw_socket->synced_data.lock);
    if (nw_socket->synced_data.base_socket && s_validate_event_loop(nw_socket->event_loop)) {

        struct nw_listener_connection_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_listener_connection_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;
        args->new_connection = new_connection;
        args->user_data = user_data;

        s_socket_acquire_internal_ref(nw_socket);
        nw_retain(new_connection);

        aws_task_init(&args->task, s_process_listener_success_task, args, "listenerSuccessTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    }
    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static void s_process_write_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
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

    s_socket_release_internal_ref(nw_socket);

    aws_mem_release(allocator, task_args);
}

static void s_schedule_write_fn(
    struct nw_socket *nw_socket,
    int error_code,
    size_t bytes_written,
    void *user_data,
    aws_socket_on_write_completed_fn *written_fn) {
    AWS_FATAL_ASSERT(s_validate_event_loop(nw_socket->event_loop));

    aws_mutex_lock(&nw_socket->synced_data.lock);

    struct nw_socket_written_args *args =
        aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_written_args));

    args->nw_socket = nw_socket;
    args->allocator = nw_socket->allocator;
    args->error_code = error_code;
    args->written_fn = written_fn;
    args->user_data = user_data;
    args->bytes_written = bytes_written;
    s_socket_acquire_internal_ref(nw_socket);

    aws_task_init(&args->task, s_process_write_task, args, "writtenTask");

    aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);

    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static int s_socket_connect_fn(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_FATAL_ASSERT(event_loop);
    AWS_FATAL_ASSERT(!socket->event_loop);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, socket->io_handle.data.handle);

    if (socket->event_loop) {
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    // Apple Network Framework uses a connection based abstraction on top of the UDP layer. We should always do an
    // "connect" action after aws_socket_init() regardless it's a UDP socket or a TCP socket.
    AWS_FATAL_ASSERT(on_connection_result);
    s_lock_socket_state(nw_socket);
    if (nw_socket->synced_state.state != INIT) {
        s_unlock_socket_state(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    s_unlock_socket_state(nw_socket);

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
        AWS_FATAL_ASSERT(0);
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
    nw_socket->os_handle.nw_connection = socket->io_handle.data.handle;
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
    nw_socket->connect_result_user_data = user_data;

    AWS_FATAL_ASSERT(socket->options.connect_timeout_ms);
    nw_socket->timeout_args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_timeout_args));

    nw_socket->timeout_args->nw_socket = nw_socket;
    nw_socket->timeout_args->allocator = socket->allocator;

    aws_task_init(
        &nw_socket->timeout_args->task,
        s_handle_socket_timeout,
        nw_socket->timeout_args,
        "NWSocketConnectionTimeoutTask");

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
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: scheduling timeout task for %llu.",
        (void *)socket,
        socket->io_handle.data.handle,
        (unsigned long long)timeout);
    nw_socket->timeout_args->task.timestamp = timeout;
    // Acquire a nw_socket for the timeout task
    s_socket_acquire_internal_ref(nw_socket);

    // The timeout task must schedule before we start the system connection. We will release the timeout args when we
    // finished a connection. If we start the system connection first, then it is possible that the connection finished
    // before timeout task scheduled, and the timeout args is already released by the time we schedule it.
    aws_event_loop_schedule_task_future(event_loop, &nw_socket->timeout_args->task, timeout);

    /* set a handler for socket state changes. This is where we find out if the connection timed out, was successful,
     * was disconnected etc .... */
    nw_connection_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
          s_schedule_connection_state_changed_fn(socket, nw_socket, nw_socket->os_handle.nw_connection, state, error);
        });
    // released when the connection state changed to nw_connection_state_cancelled
    s_socket_acquire_internal_ref(nw_socket);
    nw_connection_start(socket->io_handle.data.handle);
    nw_retain(socket->io_handle.data.handle);

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
    AWS_LOGF_TRACE(
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
    } else { // Unsupported address family
        AWS_FATAL_ASSERT(0);
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
    nw_socket->os_handle.nw_listener = socket->io_handle.data.handle;
    nw_retain(socket->io_handle.data.handle);
    nw_socket->mode = NWSM_LISTENER;

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=%p:  listen failed with error code %d", (void *)socket, aws_last_error());

        s_set_socket_state(nw_socket, socket, ERROR);

        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    socket->io_handle.set_queue = s_listener_set_dispatch_queue;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: nw_socket successfully listening",
        (void *)socket,
        socket->io_handle.data.handle);

    s_set_socket_state(nw_socket, socket, LISTENING);

    return AWS_OP_SUCCESS;
}

struct listener_state_changed_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct nw_socket *nw_socket;
    nw_listener_state_t state;
    int error;
};

static void s_process_listener_state_changed_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct listener_state_changed_args *listener_state_changed_args = args;

    struct nw_socket *nw_socket = listener_state_changed_args->nw_socket;
    nw_listener_t nw_listener = nw_socket->os_handle.nw_listener;
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

        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *aws_socket = nw_socket->synced_data.base_socket;
        if (nw_socket->on_accept_started_fn) {
            nw_socket->on_accept_started_fn(
                aws_socket,
                s_determine_socket_error(listener_state_changed_args->error),
                nw_socket->listen_accept_started_user_data);
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);

    } else if (state == nw_listener_state_ready) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: listener on port ready ", (void *)nw_socket, (void *)nw_listener);

        aws_mutex_lock(&nw_socket->synced_data.lock);
        struct aws_socket *aws_socket = nw_socket->synced_data.base_socket;
        if (aws_socket && status == AWS_TASK_STATUS_RUN_READY) {
            if (nw_socket->mode == NWSM_LISTENER) {
                aws_socket->local_endpoint.port = nw_listener_get_port(nw_socket->os_handle.nw_listener);
            }
            if (nw_socket->on_accept_started_fn) {
                nw_socket->on_accept_started_fn(aws_socket, AWS_OP_SUCCESS, nw_socket->listen_accept_started_user_data);
            }
        }
        aws_mutex_unlock(&nw_socket->synced_data.lock);

    } else if (state == nw_listener_state_cancelled) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: listener on port cancelled ", (void *)nw_socket, (void *)nw_listener);

        s_set_socket_state(nw_socket, listener_state_changed_args->socket, CLOSED);
        s_socket_release_internal_ref(nw_socket);
    }

    // Release the internal ref for the task
    s_socket_release_internal_ref(nw_socket);
    aws_mem_release(listener_state_changed_args->allocator, listener_state_changed_args);
}

static void s_schedule_listener_state_changed_fn(
    struct aws_socket *socket,
    struct nw_socket *nw_socket,
    nw_listener_state_t state,
    nw_error_t error) {

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: s_schedule_listener_state_changed_fn start...", (void *)nw_socket);

    aws_mutex_lock(&nw_socket->synced_data.lock);

    if (socket && s_validate_event_loop(nw_socket->event_loop)) {
        struct listener_state_changed_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct listener_state_changed_args));

        args->socket = socket;
        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error = error ? nw_error_get_error_code(error) : 0;
        args->state = state;

        s_socket_acquire_internal_ref(nw_socket);
        aws_task_init(&args->task, s_process_listener_state_changed_task, args, "ListenerStateChangedTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    } else if (state == nw_listener_state_cancelled) {
        // If socket is already destroyed and the listener is canceled, directly closed the internal socket.
        s_socket_release_internal_ref(nw_socket);
    }
    aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    struct aws_socket_listener_options options) {
    AWS_FATAL_ASSERT(options.on_accept_result);
    AWS_FATAL_ASSERT(accept_loop);

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
    socket->accept_result_fn = options.on_accept_result;
    socket->connect_accept_user_data = options.on_accept_result_user_data;

    nw_socket->on_accept_started_fn = options.on_accept_start_result;
    nw_socket->listen_accept_started_user_data = options.on_accept_start_user_data;

    s_set_event_loop(socket, accept_loop);

    nw_listener_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_listener_state_t state, nw_error_t error) {
          s_schedule_listener_state_changed_fn(socket, nw_socket, state, error);
        });

    nw_listener_set_new_connection_handler(socket->io_handle.data.handle, ^(nw_connection_t connection) {
      s_schedule_on_listener_success(nw_socket, AWS_OP_SUCCESS, connection, socket->connect_accept_user_data);
    });
    // this ref should be released in nw_listener_set_state_changed_handler where get state ==
    // nw_listener_state_cancelled
    s_socket_acquire_internal_ref(nw_socket);
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

    AWS_LOGF_TRACE(
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
        s_unlock_socket_state(nw_socket);
        // We would like to keep CONNECTED_READ so that we could continue processing any received data until the we got
        // the system callback indicates that the system connection has been closed in the receiving direction.
        s_set_socket_state(nw_socket, nw_socket->synced_data.base_socket, CLOSING | CONNECTED_READ);
        s_socket_release_write_ref(nw_socket);
    } else {
        s_unlock_socket_state(nw_socket);
    }
    return AWS_OP_SUCCESS;
}

static int s_socket_shutdown_dir_fn(struct aws_socket *socket, enum aws_channel_direction dir) {
    (void)dir;
    // Invalid operation so far, current nw_socket does not support both dir connection
    AWS_FATAL_ASSERT(true);
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

/* s_schedule_next_read() is called when we find that we've read all of our buffers or we preemptively know we're going
 * to want more notifications. That read data gets queued into an internal read buffer to then be vended upon a call to
 * aws_socket_read() */
static void s_schedule_next_read(struct nw_socket *nw_socket) {
    s_lock_socket_synced_data(nw_socket);

    if (nw_socket->synced_data.read_scheduled) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: there is already read queued, do not queue further read",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
        s_unlock_socket_synced_data(nw_socket);
        return;
    }
    struct aws_socket *socket = nw_socket->synced_data.base_socket;

    s_unlock_socket_synced_data(nw_socket);
    if (!socket) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read to because socket is not connected",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
        aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        return;
    }

    s_lock_socket_state(nw_socket);
    if (!(nw_socket->synced_state.state & CONNECTED_READ)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read to because socket is not connected",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
        aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        s_unlock_socket_state(nw_socket);
        return;
    }
    s_unlock_socket_state(nw_socket);

    // Acquire nw_socket as we called nw_connection_receive, and the ref will be released when the handler is
    // called.
    s_socket_acquire_internal_ref(nw_socket);

    /* read and let me know when you've done it. */
    nw_connection_receive(
        socket->io_handle.data.handle,
        1,
        UINT32_MAX,
        ^(dispatch_data_t data, nw_content_context_t context, bool is_complete, nw_error_t error) {
          s_lock_socket_synced_data(nw_socket);
          nw_socket->synced_data.read_scheduled = false;
          s_unlock_socket_synced_data(nw_socket);

          bool complete = is_complete;
          if (!error || nw_error_get_error_code(error) == 0) {
              int error = AWS_ERROR_SUCCESS;

              /* For protocols such as TCP, `is_complete` will be marked when the entire stream has be closed in the
               * reading direction. For protocols such as UDP, this will be marked when the end of a datagram has
               * been reached. */
              if (is_complete && nw_content_context_get_is_final(context)) {

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
                          (void *)nw_socket->os_handle.nw_connection);

                      complete = true;
                      aws_raise_error(AWS_IO_SOCKET_CLOSED);
                      error = AWS_IO_SOCKET_CLOSED;
                  }
                  aws_mutex_unlock(&nw_socket->synced_data.lock);
              }

              // The callback should be fired before schedule to avoid
              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: queued read buffer of size %d",
                  (void *)nw_socket,
                  (void *)nw_socket->os_handle.nw_connection,
                  data ? (int)dispatch_data_get_size(data) : 0);

              s_schedule_on_readable(nw_socket, error, data, complete);

              // Try schedule next read in case we got more to read
              s_schedule_next_read(nw_socket);

          } else {
              int error_code = s_determine_socket_error(nw_error_get_error_code(error));
              aws_raise_error(error_code);

              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: error in read callback %d",
                  (void *)nw_socket,
                  (void *)nw_socket->os_handle.nw_connection,
                  error_code);
              // the data might still be partially available on an error
              s_schedule_on_readable(nw_socket, error_code, data, complete);
          }

          s_socket_release_internal_ref(nw_socket);
        });

    s_lock_socket_synced_data(nw_socket);
    nw_socket->synced_data.read_scheduled = true;
    s_unlock_socket_synced_data(nw_socket);
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

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: s_schedule_next_read : s_socket_subscribe_to_readable_events_fn.",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection);
    s_schedule_next_read(nw_socket);
    return AWS_OP_SUCCESS;
}

// WARNING: This function should never lock!!!! aws_socket_read() should always called on event loop thread,
// which means we already acquire a necessary lock there.
static int s_socket_read_fn(struct aws_socket *socket, struct aws_byte_buf *read_buffer, size_t *amount_read) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_FATAL_ASSERT(amount_read);

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
        if (!(nw_socket->synced_state.state & CONNECTED_READ)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket is not connected to read.",
                (void *)socket,
                socket->io_handle.data.handle);
            return aws_raise_error(AWS_IO_SOCKET_CLOSED);
        }

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: s_schedule_next_read : aws_socket_read() empty queue.",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);

        s_schedule_next_read(nw_socket);
        *amount_read = 0;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

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

                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: Starting read dispatch data region offset: %lu, buffer %p, with size %lu.",
                    (void *)socket,
                    socket->io_handle.data.handle,
                    offset,
                    buffer,
                    size);

                if (read_node->resume_region && offset < read_node->resume_region) {
                    AWS_LOGF_TRACE(
                        AWS_LS_IO_SOCKET,
                        "id=%p handle=%p: Skipped dispatch data region region : %lu, looking for region: %lu",
                        (void *)socket,
                        socket->io_handle.data.handle,
                        offset,
                        read_node->resume_region);
                    return true;
                }
                size_t to_copy = aws_min_size(max_to_read, size - read_node->region_offset);
                aws_byte_buf_write(read_buffer, (const uint8_t *)buffer + read_node->region_offset, to_copy);
                max_to_read -= to_copy;
                *amount_read += to_copy;
                read_node->region_offset += to_copy;
                if (read_node->region_offset == size) {
                    read_node->region_offset = 0;
                    return true;
                }
                read_node->resume_region = offset;
                return false;
            });

        if (read_completed) {
            aws_linked_list_remove(node);
            s_destroy_read_queue_node(read_node);
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read of %d",
            (void *)socket,
            socket->io_handle.data.handle,
            (int)*amount_read);
    }

    /* keep reading buffers */
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
    if (!(nw_socket->synced_state.state & CONNECTED_WRITE)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot write to because it is not connected",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    AWS_FATAL_ASSERT(written_fn);

    dispatch_data_t data = dispatch_data_create(cursor->ptr, cursor->len, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    s_socket_acquire_internal_ref(nw_socket);
    s_socket_acquire_write_ref(nw_socket);

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
                  (void *)nw_socket->os_handle.nw_connection,
                  error_code);
          }

          size_t written_size = dispatch_data_get_size(data);
          AWS_LOGF_TRACE(
              AWS_LS_IO_SOCKET,
              "id=%p handle=%p: send written size %d",
              (void *)nw_socket,
              (void *)nw_socket->os_handle.nw_connection,
              (int)written_size);
          s_schedule_write_fn(nw_socket, error_code, data ? written_size : 0, user_data, written_fn);
          s_socket_release_write_ref(nw_socket);
          s_socket_release_internal_ref(nw_socket);
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

#ifndef PREAMBLE_H
#define PREAMBLE_H
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
#include <vcc.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

/* Fake-up sys/types.h */
typedef signed int ssize_t;

/* Fake-up stdbool.h */
typedef int bool;
const int true = 1;
const int false = 0;

/* Definitions from epoll.h */
typedef union epoll_data
{
  _(backing_member) void *ptr;
  int fd; 
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event
{
  uint32_t events;        /* Epoll events */
  _(inline) epoll_data_t data;        /* User data variable */
};

enum EPOLL_EVENTS
  {
    EPOLLIN = 0x001,
#define EPOLLIN EPOLLIN
    EPOLLPRI = 0x002,
#define EPOLLPRI EPOLLPRI
    EPOLLOUT = 0x004,
#define EPOLLOUT EPOLLOUT
    EPOLLRDNORM = 0x040,
#define EPOLLRDNORM EPOLLRDNORM
    EPOLLRDBAND = 0x080,
#define EPOLLRDBAND EPOLLRDBAND
    EPOLLWRNORM = 0x100,
#define EPOLLWRNORM EPOLLWRNORM
    EPOLLWRBAND = 0x200,
#define EPOLLWRBAND EPOLLWRBAND
    EPOLLMSG = 0x400,
#define EPOLLMSG EPOLLMSG
    EPOLLERR = 0x008,
#define EPOLLERR EPOLLERR
    EPOLLHUP = 0x010,
#define EPOLLHUP EPOLLHUP
    EPOLLRDHUP = 0x2000,
#define EPOLLRDHUP EPOLLRDHUP
    EPOLLONESHOT = (1 << 30),
#define EPOLLONESHOT EPOLLONESHOT
    EPOLLET = (1 << 31)
#define EPOLLET EPOLLET
  };

#define EPOLL_CTL_ADD 1        /* Add a file decriptor to the interface.  */
#define EPOLL_CTL_DEL 2        /* Remove a file decriptor from the interface.  */
#define EPOLL_CTL_MOD 3        /* Change file decriptor epoll_event structure.  */

struct abstract_os_t {
  int unused;
  _(ghost \bool watched[int])
} abstract_os_data;
struct abstract_os_t *abstract_os = &abstract_os_data;

int epoll_ctl (int __epfd, int __op, int __fd, struct epoll_event *__event)
  _(ensures \result == 0 && __op == EPOLL_CTL_ADD ==>  abstract_os->watched[__fd])
  _(ensures \result == 0 && __op == EPOLL_CTL_DEL ==> !abstract_os->watched[__fd])
;

struct epoll_event_data;
int epoll_wait(int __epfd, struct epoll_event *__events, int maxevents, int timeout)
  _(ensures \result <= maxevents)
  /*TODO: use explicit triggers for quantifier instantiation*/
  _(ensures \forall int i; {:level 2} 0 <= i && i < \result ==> \wrapped((struct epoll_event_data *)__events[i].data.ptr))
  _(writes \extent((struct epoll_event[(unsigned)maxevents]) __events))
  _(ensures \extent_mutable((struct epoll_event[(unsigned)maxevents]) __events))
;

int epoll_create(int size)
  _(requires 0 < size)
;

/* Definitions from aws/common/macros.h */
#define AWS_CONTAINER_OF(ptr, type, member) ((type *)((uint8_t *)(ptr)-offsetof(type, member)))
#define AWS_UNLIKELY(x) x

/* Definitions from aws/common/assert.h */
/* Convert into VCC assertions */
#define AWS_ASSERT(x) _(assert x)
#define AWS_PRECONDITION(x) _(assert x)

/* Definitions from aws/common/logging.h (no-ops for proof) */
#define AWS_LOGF_INFO(...)
#define AWS_LOGF_TRACE(...)
#define AWS_LOGF_DEBUG(...)
#define AWS_LOGF_ERROR(...)
#define AWS_LOGF_FATAL(...)

/* Definitions from aws/common/clock.h */
enum aws_timestamp_unit {
    AWS_TIMESTAMP_SECS = 1,
    AWS_TIMESTAMP_MILLIS = 1000,
    AWS_TIMESTAMP_MICROS = 1000000,
    AWS_TIMESTAMP_NANOS = 1000000000,
};

uint64_t aws_timestamp_convert(
    uint64_t timestamp,
    enum aws_timestamp_unit convert_from,
    enum aws_timestamp_unit convert_to,
    uint64_t *remainder);

/* Definitions from aws/common/error.h */
#define AWS_OP_SUCCESS (0)
#define AWS_OP_ERR (-1)

enum aws_common_error {
    AWS_ERROR_SUCCESS = 0,
    AWS_ERROR_OOM,
    AWS_ERROR_UNKNOWN,
    AWS_ERROR_SHORT_BUFFER,
    AWS_ERROR_OVERFLOW_DETECTED,
    AWS_ERROR_UNSUPPORTED_OPERATION,
    AWS_ERROR_INVALID_BUFFER_SIZE,
    AWS_ERROR_INVALID_HEX_STR,
    AWS_ERROR_INVALID_BASE64_STR,
    AWS_ERROR_INVALID_INDEX,
    AWS_ERROR_THREAD_INVALID_SETTINGS,
    AWS_ERROR_THREAD_INSUFFICIENT_RESOURCE,
    AWS_ERROR_THREAD_NO_PERMISSIONS,
    AWS_ERROR_THREAD_NOT_JOINABLE,
    AWS_ERROR_THREAD_NO_SUCH_THREAD_ID,
    AWS_ERROR_THREAD_DEADLOCK_DETECTED,
    AWS_ERROR_MUTEX_NOT_INIT,
    AWS_ERROR_MUTEX_TIMEOUT,
    AWS_ERROR_MUTEX_CALLER_NOT_OWNER,
    AWS_ERROR_MUTEX_FAILED,
    AWS_ERROR_COND_VARIABLE_INIT_FAILED,
    AWS_ERROR_COND_VARIABLE_TIMED_OUT,
    AWS_ERROR_COND_VARIABLE_ERROR_UNKNOWN,
    AWS_ERROR_CLOCK_FAILURE,
    AWS_ERROR_LIST_EMPTY,
    AWS_ERROR_DEST_COPY_TOO_SMALL,
    AWS_ERROR_LIST_EXCEEDS_MAX_SIZE,
    AWS_ERROR_LIST_STATIC_MODE_CANT_SHRINK,
    AWS_ERROR_PRIORITY_QUEUE_FULL,
    AWS_ERROR_PRIORITY_QUEUE_EMPTY,
    AWS_ERROR_PRIORITY_QUEUE_BAD_NODE,
    AWS_ERROR_HASHTBL_ITEM_NOT_FOUND,
    AWS_ERROR_INVALID_DATE_STR,
    AWS_ERROR_INVALID_ARGUMENT,
    AWS_ERROR_RANDOM_GEN_FAILED,
    AWS_ERROR_MALFORMED_INPUT_STRING,
    AWS_ERROR_UNIMPLEMENTED,
    AWS_ERROR_INVALID_STATE,
    AWS_ERROR_ENVIRONMENT_GET,
    AWS_ERROR_ENVIRONMENT_SET,
    AWS_ERROR_ENVIRONMENT_UNSET,
    AWS_ERROR_STREAM_UNSEEKABLE,
    AWS_ERROR_NO_PERMISSION,
    AWS_ERROR_FILE_INVALID_PATH,
    AWS_ERROR_MAX_FDS_EXCEEDED,
    AWS_ERROR_SYS_CALL_FAILURE,
    AWS_ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED,
    AWS_ERROR_STRING_MATCH_NOT_FOUND,

    AWS_ERROR_END_COMMON_RANGE = 0x03FF
};

int aws_raise_error(int err)
    _(ensures \result == AWS_OP_ERR)
;

/* Forward declarations */
struct epoll_loop;
struct aws_allocator;
struct aws_linked_list_node;
struct aws_mutex;
struct aws_io_handle;

/* Definitions from aws/common/allocator.h */
struct aws_allocator {
    void *(*mem_acquire)(struct aws_allocator *allocator, size_t size);
    void (*mem_release)(struct aws_allocator *allocator, void *ptr);
    /* Optional method; if not supported, this pointer must be NULL */
    void *(*mem_realloc)(struct aws_allocator *allocator, void *oldptr, size_t oldsize, size_t newsize);
    /* Optional method; if not supported, this pointer must be NULL */
    void *(*mem_calloc)(struct aws_allocator *allocator, size_t num, size_t size);
    void *impl;
    _(invariant mem_acquire->\valid)
    _(invariant mem_release->\valid)
    _(invariant mem_realloc == NULL || mem_release->\valid)
    _(invariant mem_calloc == NULL || mem_calloc->\valid)
};

#define aws_mem_calloc(a,n,s) malloc(n*s)
#define aws_mem_release(a,o) free(o)

/* Definitions from aws/common/array_list.h */
struct aws_array_list {
    struct aws_allocator *alloc;
    size_t current_size;
    size_t length;
    size_t item_size;
    void *data;
};

/* Definitions from aws/common/priority_queue.h */
struct aws_priority_queue_node {
    size_t current_index;
};

/* VCC change: fnptr declaration
cio function pointer declaration can't be parsed
typedef int(aws_priority_queue_compare_fn)(const void *a, const void *b);
replaced with */
typedef int(* aws_priority_queue_compare_fn_ptr)(const void *a, const void *b);

struct aws_priority_queue {
    aws_priority_queue_compare_fn_ptr pred; /*< VCC change: fnptr */
    _(inline) struct aws_array_list container;
    _(inline) struct aws_array_list backpointers;
    _(invariant pred->\valid)
};

/* Definitions from aws/common/task_scheduler.h */
struct aws_task;

typedef enum aws_task_status {
    AWS_TASK_STATUS_RUN_READY,
    AWS_TASK_STATUS_CANCELED,
} aws_task_status;

/* VCC change: fnptr declaration */
typedef void(* aws_task_fn_ptr)(struct aws_task *task, void *arg, enum aws_task_status)
#ifdef UNSUB_TASK_FN_PTR
  _(requires \malloc_root((struct epoll_event_data *)arg))
  _(writes \extent((struct epoll_event_data *)arg))
#elif defined(STOP_TASK_FN_PTR)
  _(updates epoll_loop_of(event_loop_of(arg))::status)
  _(updates &epoll_loop_of(event_loop_of(arg))->stop_task_ptr)
  _(requires \thread_local(event_loop_of(arg)))
#endif
;

struct aws_task {
    aws_task_fn_ptr fn; /*< VCC change: fnptr */
    void *arg;
    uint64_t timestamp;
    struct aws_linked_list_node node;
    struct aws_priority_queue_node priority_queue_node;
    const char *type_tag;
    size_t reserved;
    _(invariant \mine(&node))
    _(invariant \mine(&priority_queue_node))
};

void aws_task_init(struct aws_task *task, aws_task_fn_ptr aws_task_fn, void *arg, const char *type_tag)
  _(requires \thread_local(task))
  _(writes task)
  _(ensures \wrapped(task))
  _(ensures task->fn == aws_task_fn)
  _(ensures task->arg == arg)
  _(ensures task->type_tag == type_tag)
;

struct aws_task_scheduler {
    struct aws_allocator *alloc;
    struct aws_priority_queue timed_queue; /* Tasks scheduled to run at specific times */
    struct aws_linked_list timed_list;     /* If timed_queue runs out of memory, further timed tests are stored here */
    struct aws_linked_list asap_list;      /* Tasks scheduled to run as soon as possible */
    _(invariant \mine(&timed_queue))
    _(invariant \mine(&timed_list))
    _(invariant \mine(&asap_list))
};

int aws_task_scheduler_init(struct aws_task_scheduler *scheduler, struct aws_allocator *allocator)
    _(writes \extent(&scheduler->timed_list))
    _(writes \extent(&scheduler->asap_list))
    _(ensures \extent_mutable(&scheduler->timed_list))
    _(ensures \extent_mutable(&scheduler->asap_list))
    _(ensures \result == AWS_OP_SUCCESS <==>
        scheduler->timed_queue.pred.\valid &&
        (scheduler->timed_list.head.next == &scheduler->timed_list.tail && scheduler->timed_list.length == 0) &&
        (scheduler->asap_list.head.next == &scheduler->asap_list.tail && scheduler->asap_list.length == 0)
     )
;

void aws_task_scheduler_schedule_now(struct aws_task_scheduler *scheduler, struct aws_task *task)
    _(updates scheduler)
;

void aws_task_scheduler_schedule_future(struct aws_task_scheduler *scheduler, struct aws_task *task, uint64_t time_to_run)
    _(updates scheduler)
;

void aws_task_scheduler_run_all(struct aws_task_scheduler *scheduler, uint64_t current_time)
    _(updates scheduler)
;

void aws_task_scheduler_clean_up(struct aws_task_scheduler *scheduler)
    _(updates scheduler)
;

void aws_task_scheduler_cancel_task(struct aws_task_scheduler *scheduler, struct aws_task *task)
    _(updates scheduler)
;

bool aws_task_scheduler_has_tasks(const struct aws_task_scheduler *scheduler, uint64_t *next_task_time);

/* Definitions from aws/common/atomics.h */
struct aws_atomic_var {
  void *value;
};

/* VCC change: remove volatile annotation */
void aws_atomic_init_int(/*volatile*/ struct aws_atomic_var *var, size_t n)
  _(writes &(var->value))
;

void aws_atomic_init_ptr(/*volatile*/ struct aws_atomic_var *var, void *p)
  _(writes &(var->value))
;

void *aws_atomic_load_ptr(/*volatile*/ struct aws_atomic_var *var)
;

uint64_t aws_atomic_load_int(/*volatile const*/ struct aws_atomic_var *var)
;

void aws_atomic_store_int(/*volatile*/ struct aws_atomic_var *var, size_t n)
  _(writes &(var->value))
;

bool aws_atomic_compare_exchange_ptr(/*volatile*/ struct aws_atomic_var *var, void **expected, void *desired)
  _(writes &(var->value))
;

void aws_atomic_store_ptr(/*volatile*/ struct aws_atomic_var *var, void *val)
  _(writes &(var->value))
;

/* Fake-up pthread.h */
typedef uint64_t pthread_t;

/* Definitions from aws/common/thread.h */
enum aws_thread_detach_state {
    AWS_THREAD_NOT_CREATED = 1,
    AWS_THREAD_JOINABLE,
    AWS_THREAD_JOIN_COMPLETED,
};

typedef pthread_t aws_thread_id_t;

struct aws_thread {
    struct aws_allocator *allocator;
    enum aws_thread_detach_state detach_state;
    aws_thread_id_t thread_id;
};

struct aws_thread_options {
    size_t stack_size;
    int32_t cpu_id;
};

_(pure) aws_thread_id_t aws_thread_current_thread_id(void)
    _(ensures \result == \addr(\me))
;

int aws_thread_init(struct aws_thread *thread, struct aws_allocator *allocator)
  _(requires allocator->\valid)
  _(writes \span(thread))
  _(ensures \extent_mutable(thread))
;

void aws_thread_clean_up(struct aws_thread *thread)
  _(writes \span(thread))
  _(ensures \extent_mutable(thread))
;

_(pure) bool aws_thread_thread_id_equal(aws_thread_id_t t1, aws_thread_id_t t2)
  _(ensures \result == (t1 == t2))
;

/* Pure from point-of-view of the event loop since the following functions lock and mutate private aws-c-common state */
_(pure) void aws_thread_increment_unjoined_count();
_(pure) void aws_thread_decrement_unjoined_count();

/* Definitions from aws/io/io.h */
enum aws_io_event_type {
    AWS_IO_EVENT_TYPE_READABLE = 1,
    AWS_IO_EVENT_TYPE_WRITABLE = 2,
    AWS_IO_EVENT_TYPE_REMOTE_HANG_UP = 4,
    AWS_IO_EVENT_TYPE_CLOSED = 8,
    AWS_IO_EVENT_TYPE_ERROR = 16,
};

struct aws_io_handle {
    _(inline) struct {
        int fd;
        void *handle;
    } data;
    void *additional_data;
    _(invariant valid_fd(data.fd))
};

/* VCC change: fnptr declaration */
typedef int(* aws_io_clock_fn_ptr)(uint64_t *timestamp)
  _(writes timestamp)
;

/* Definitions from aws/io/event_loop.h */
struct aws_event_loop_vtable;

struct aws_event_loop_options {
    aws_io_clock_fn_ptr clock; /*< VCC change: fnptr */
    struct aws_thread_options *thread_options;
    _(invariant clock->\valid)
    _(invariant thread_options != NULL <==> \mine(thread_options))
};

_(claimable) struct aws_event_loop {
    struct aws_event_loop_vtable *vtable;
    struct aws_allocator *alloc;
    aws_io_clock_fn_ptr clock;           /*< VCC change: fnptr */
/*  struct aws_hash_table local_data; */ /*< VCC change: not modeled */
    void *impl_data;
    /*TODO: allocator is shared and closed*/
    _(invariant clock->\valid)
    _(invariant \mine((struct epoll_loop *)impl_data))
};

/* VCC change: fnptr declaration */
typedef void(* aws_event_loop_on_event_fn_ptr)(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data _(ghost \claim(c)))
    _(requires \wrapped(c) && \claims(c, event_loop->\closed))
    _(requires \nested(handle))
    _(writes &epoll_loop_of(event_loop)->should_process_task_pre_queue)
;

/* Definitions from aws/common/linked_list.h */
struct aws_linked_list_node {
    struct aws_linked_list_node *next;
    struct aws_linked_list_node *prev;
};

struct aws_linked_list {
    struct aws_linked_list_node head;
    struct aws_linked_list_node tail;
    _(ghost \natural length)
    _(invariant \mine(&head))
    _(invariant \mine(&tail))
    _(invariant (0 == length) <==> (head.next == &tail))
};

void aws_linked_list_init(struct aws_linked_list *list)
  _(requires \thread_local(list))
  _(writes \extent(list))
  _(ensures \extent_mutable(list))
  _(ensures list->head.next == &list->tail)
  _(ensures list->tail.next == NULL)
  _(ensures list->tail.prev == &list->head)
  _(ensures list->head.prev == NULL)
  _(ensures list->length == 0)
;

_(pure) bool aws_linked_list_empty(const struct aws_linked_list *list)
    _(requires \wrapped(list))
    _(reads &list->length)
    _(ensures \result == (list->length == 0))
    _(decreases 0)
{
    return list->head.next == &list->tail;
}

/* Specialized for linked lists containing tasks */
struct aws_linked_list_node *aws_linked_list_pop_front(struct aws_linked_list *list _(out struct aws_task * task))
    /* general: */
    _(maintains \wrapped(list))
    _(requires 0 < list->length)
    _(ensures (\old(list->length) - 1) == list->length)
    _(writes list)
    _(decreases 0)
    /* specialized: */
    _(ensures task == AWS_CONTAINER_OF(\result, struct aws_task, node))
    _(ensures \thread_local(task))
    _(ensures task->fn->\valid)
;

/* We omit `task == AWS_CONTAINER_OF(node, struct aws_task, node)`
because VCC's memory model can't prove this when this occurs in
`s_schedule_task_common` */
void aws_linked_list_push_back(struct aws_linked_list *list, struct aws_linked_list_node *node _(ghost struct aws_task *task))
    /* general: */
    _(updates list)
    /* specialized: */
    _(requires task->fn->\valid)
;

void aws_linked_list_swap_contents(struct aws_linked_list *a, struct aws_linked_list *b)
    _(updates a)
    _(updates b)
;

/* Definitions from source/linux/epoll_event_loop.c */
struct epoll_loop {
    _(group scheduler)
    _(:scheduler) struct aws_task_scheduler scheduler;
    struct aws_thread thread_created_on;
    struct aws_thread_options thread_options;
    aws_thread_id_t thread_joined_to;
    struct aws_atomic_var running_thread_id;
    _(group read_handle)
    _(:read_handle) struct aws_io_handle read_task_handle;
    struct aws_io_handle write_task_handle;
    struct aws_mutex task_pre_queue_mutex;
    _(group queue)
    _(:queue) struct aws_linked_list task_pre_queue;
    _(group stop_task)
    _(:stop_task) struct aws_task stop_task;
    _(:stop_task) struct aws_atomic_var stop_task_ptr;
    int epoll_fd;
    _(group status)
    _(:status) bool should_process_task_pre_queue;
    _(:status) bool should_continue;
    _(invariant valid_fd(epoll_fd))
    /* scheduler */
    _(invariant \mine(&thread_created_on))
    _(invariant \mine(&running_thread_id))
    /* read_handle */
    _(invariant \mine(&write_task_handle))
    _(invariant \mine(&task_pre_queue_mutex))
    /* task_pre_queue */
    /* stop_task */
    /* stop_task_ptr */
    _(invariant task_pre_queue_mutex.protected_obj == &task_pre_queue)
    _(invariant task_pre_queue_mutex.\claim_count == 1)
};

struct epoll_event_data {
    struct aws_allocator *alloc;
    struct aws_io_handle *handle;
    aws_event_loop_on_event_fn_ptr on_event; /*< VCC change: fnptr */
    void *user_data;
    struct aws_task cleanup_task;
    bool is_subscribed; /* false when handle is unsubscribed, but this struct hasn't beeen cleaned up yet */
    _(invariant \mine(handle))
    _(invariant ((struct epoll_event_data *)handle->additional_data) == \this)
    _(invariant on_event->\valid)
    _(invariant \mine(&cleanup_task))
};

/* VCC mutex contract */
/* VCC change: replace mutex implementation with VCC contract */
#define AWS_MUTEX_INIT { .locked = 0 }

_(claimable) _(volatile_owns) struct aws_mutex {
    volatile int locked; /* 0=>unlocked / 1=>locked */
    _(ghost \object protected_obj)
    _(invariant locked == 0 ==> \mine(protected_obj))
};

void aws_mutex_lock(struct aws_mutex *l _(ghost \claim c))
    _(always c, l->\closed)
    _(ensures \wrapped(l->protected_obj) && \fresh(l->protected_obj))
    _(ensures l->locked == 1)
;

void aws_mutex_unlock(struct aws_mutex *l _(ghost \claim c))
    _(always c, l->\closed)
    _(requires l->protected_obj != c)
    _(writes l->protected_obj)
    _(requires \wrapped(l->protected_obj))
    _(ensures l->locked == 0)
;

/* Useful definitions */
_(def bool valid_fd(int fd) {
  return 0 <= fd;
})

_(def struct aws_event_loop *event_loop_of(void *arg) {
  return (struct aws_event_loop *)arg;
})

_(def struct epoll_loop *epoll_loop_of(struct aws_event_loop *event_loop) {
  return (struct epoll_loop *)event_loop->impl_data;
})

/*
 * This predicate (which implies the object invariant properties of
 * epoll_event_data) means the heap looks like this:
 *
 * handle --.additional_data--> epoll_event_data --.on_event--> valid fn
 *     ^                         /            \
 *      `--------------.handle--'              '--.user_data--> (can be NULL)
 */
_(def \bool wf_cio_handle(struct aws_io_handle *handle) {
  return \nested(handle) && handle->\closed &&
         \malloc_root((struct epoll_event_data *)handle->additional_data) &&
         \wrapped((struct epoll_event_data *)handle->additional_data) &&
         (handle->\owner == (struct epoll_event_data *)handle->additional_data);
})

#define current_thread_owns_event_loop(event_loop) \
  \addr(\me) == \addr(event_loop->\owner)

#define ownership_of_epoll_loop_objects(loop) \
    (\wrapped(loop::scheduler)                       \
        && \wrapped(&loop->scheduler)                \
        && \wrapped(loop::read_handle)               \
        && \wrapped(&loop->read_task_handle)         \
        && \wrapped(loop::stop_task)                 \
        && \wrapped(&loop->stop_task)                \
        && \wrapped(&loop->stop_task_ptr)            \
        && \wrapped(loop::queue)                     \
        && \wrapped(loop::status)                    \
        && \fresh(loop::scheduler)                   \
        && \fresh(&loop->scheduler)                  \
        && \fresh(loop::read_handle)                 \
        && \fresh(&loop->read_task_handle)           \
        && \fresh(loop::stop_task)                   \
        && \fresh(&loop->stop_task)                  \
        && \fresh(&loop->stop_task_ptr)              \
        && \fresh(loop::queue)                       \
        && \fresh(&loop->task_pre_queue)             \
        && \fresh(loop::status))

/* Specifications for epoll_loop functions */
static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn_ptr on_event, /*< VCC change: fnptr */
    void *user_data
    _(ghost \claim(c_event_loop))
)
    _(always c_event_loop, event_loop->\closed) /*< the event_loop won't be changed or destroyed underneath us */
    _(requires \wrapped(handle))                /*< wrapped means closed (the handle is valid) and owned by the current thread */
    _(requires on_event->\valid)                /*< valid function pointer */
    /* user_data may be NULL */
    _(ensures \result == AWS_OP_SUCCESS <==> wf_cio_handle(handle))
    _(ensures \result == AWS_OP_SUCCESS  ==> \fresh((struct epoll_event_data *)handle->additional_data))
    _(writes handle)
;

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    _(maintains \wrapped(event_loop))           /*< current thread owns event loop (i.e., current thread is the event loop thread) */
    _(always c_event_loop, event_loop->\closed) /*< required for schedule call */
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(requires wf_cio_handle(handle))
    _(ensures \result == AWS_OP_SUCCESS <==> !\nested(handle))
    _(ensures \result != AWS_OP_SUCCESS <==> wf_cio_handle(handle))
    _(writes ((struct epoll_event_data *)handle->additional_data))
    _(updates &epoll_loop_of(event_loop)->scheduler)
;

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    _(always c_event_loop, event_loop->\closed)
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(requires \thread_local(task))
    _(requires \wrapped(task))
    _(requires task->fn->\valid)
    _(writes task)
    _(updates &epoll_loop_of(event_loop)->scheduler)
;

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    _(always c_event_loop, event_loop->\closed)
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(requires \thread_local(task))
    _(requires \wrapped(task))
    _(requires task->fn->\valid)
    _(writes task)
    _(updates &epoll_loop_of(event_loop)->scheduler)
;

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop))
)
    _(always c_event_loop, event_loop->\closed)
    _(ensures \result ==> current_thread_owns_event_loop(event_loop))
;

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task)
    _(requires \wrapped(event_loop))
    _(updates &epoll_loop_of(event_loop)->scheduler)
;

static void s_process_task_pre_queue(struct aws_event_loop *event_loop _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex)))
    _(always c_event_loop, event_loop->\closed)
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(requires \thread_local(&epoll_loop_of(event_loop)->read_task_handle))
    _(requires (&epoll_loop_of(event_loop)->read_task_handle)->\closed)
    _(writes &epoll_loop_of(event_loop)->should_process_task_pre_queue)
    _(updates &epoll_loop_of(event_loop)->scheduler)
;

static void s_stop_task(struct aws_task *task, void *args, enum aws_task_status status)
    _(requires \thread_local(event_loop_of(args)))
    _(updates epoll_loop_of(event_loop_of(args))::status)
    _(updates &epoll_loop_of(event_loop_of(args))->stop_task_ptr)
;

static int s_stop(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop))
    _(ghost \claim(c_mutex))
)
    /* wrapped0 means the claim_count of c_event_loop is 0 (i.e., notionally,
    all of the claims handed to client threads have been destroyed), so
    client threads may no longer call any further event loop API calls. */
    _(maintains \wrapped0(c_event_loop) && \claims(c_event_loop, event_loop->\closed))
    _(maintains \wrapped0(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(requires \wrapped(&epoll_loop_of(event_loop)->stop_task))
    _(writes (&epoll_loop_of(event_loop)->stop_task))
    _(updates epoll_loop_of(event_loop)::status)
    _(updates &epoll_loop_of(event_loop)->scheduler)
    _(updates &epoll_loop_of(event_loop)->stop_task_ptr)
;

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex))
)
    _(requires c_event_loop != c_mutex)
    _(requires \wrapped0(c_event_loop) && \claims(c_event_loop, event_loop->\closed) && \claims_object(c_event_loop, event_loop))
    _(writes c_event_loop, event_loop)
    _(ensures !c_event_loop->\closed)
    _(ensures \wrapped0(event_loop) && \nested(epoll_loop_of(event_loop)))
    _(ensures ownership_of_epoll_loop_objects(epoll_loop_of(event_loop)))
    _(ensures epoll_loop_of(event_loop)->task_pre_queue_mutex.locked == 0)
    _(maintains \malloc_root(epoll_loop_of(event_loop)))
    _(maintains \wrapped0(c_mutex) && \claims_object(c_mutex, &epoll_loop_of(event_loop)->task_pre_queue_mutex))
;

static int s_run(struct aws_event_loop *event_loop _(ghost \claim(c_mutex)))
    _(requires
        \wrapped0(event_loop) &&
        \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop)->task_pre_queue_mutex)))
    _(writes &epoll_loop_of(event_loop)->should_continue)
;

static void s_on_tasks_to_schedule(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data _(ghost \claim(c_event_loop))
)
    _(always c_event_loop, event_loop->\closed)
    _(requires \nested(handle))
    _(writes &epoll_loop_of(event_loop)->should_process_task_pre_queue)
;

static void s_main_loop(void *args _(ghost \claim(c_mutex)))
    _(requires \wrapped(event_loop_of(args)))
    _(requires \not_shared(event_loop_of(args)))
    _(requires \wrapped(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(event_loop_of(args))->task_pre_queue_mutex)))
    _(requires \wrapped(&epoll_loop_of(event_loop_of(args))->read_task_handle))
    _(updates &epoll_loop_of(event_loop_of(args))->scheduler)
    _(updates &epoll_loop_of(event_loop_of(args))->running_thread_id)
    _(writes event_loop_of(args))
    _(writes &epoll_loop_of(event_loop_of(args))->read_task_handle)
    _(writes (struct epoll_event_data *)(epoll_loop_of(event_loop_of(args))->read_task_handle.additional_data))
    _(writes &epoll_loop_of(event_loop_of(args))->should_process_task_pre_queue)
;

struct aws_event_loop *aws_event_loop_new_default(
    struct aws_allocator *alloc,
    aws_io_clock_fn_ptr clock /*< VCC change: fnptr */
    _(out \claim(c_mutex))
)
    _(requires \wrapped(alloc))
    _(requires clock->\valid)
    _(ensures \result == NULL ||
       (\wrapped0(\result) &&
        \fresh(\result) && \malloc_root(\result) &&
        \fresh(epoll_loop_of(\result)) && \malloc_root(epoll_loop_of(\result)) &&
        ownership_of_epoll_loop_objects(epoll_loop_of(\result)) &&
        \fresh(c_mutex) && \wrapped0(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(\result)->task_pre_queue_mutex))))
;

struct aws_event_loop *aws_event_loop_new_default_with_options(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options
    _(out \claim(c_mutex))
)
    _(requires \wrapped(alloc))
    _(maintains \wrapped(options))
    _(ensures \result == NULL ||
       (\wrapped0(\result) &&
        \fresh(\result) && \malloc_root(\result) &&
        \fresh(epoll_loop_of(\result)) && \malloc_root(epoll_loop_of(\result)) &&
        ownership_of_epoll_loop_objects(epoll_loop_of(\result)) &&
        \fresh(c_mutex) && \wrapped0(c_mutex) && \claims_object(c_mutex, &(epoll_loop_of(\result)->task_pre_queue_mutex))))
;

static void s_destroy(struct aws_event_loop *event_loop
    _(ghost \claim(c_event_loop)) _(ghost \claim(c_mutex))
)
    _(requires \malloc_root(event_loop))
    _(requires \malloc_root(epoll_loop_of(event_loop)))
    _(requires c_event_loop != c_mutex)
    _(requires \wrapped0(c_event_loop) && \claims_object(c_event_loop, event_loop))
    _(requires \wrapped0(c_mutex) && \claims_object(c_mutex, &epoll_loop_of(event_loop)->task_pre_queue_mutex))
    _(requires \wrapped(&epoll_loop_of(event_loop)->scheduler))
    _(requires \wrapped(epoll_loop_of(event_loop)::status))
    _(requires \wrapped(&epoll_loop_of(event_loop)->stop_task))
    _(writes &epoll_loop_of(event_loop)->scheduler)
    _(writes epoll_loop_of(event_loop)::status)
    _(writes &epoll_loop_of(event_loop)->stop_task)
    _(writes event_loop, c_event_loop, c_mutex)
    _(updates &epoll_loop_of(event_loop)->stop_task_ptr)
;

/* clang-format on */
#endif PREAMBLE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/future.h>

static void s_future_base_result_dtor(struct aws_future_base *future, void *result_addr) {
    switch (future->type) {
        case AWS_FUTURE_T_BY_VALUE_WITH_CLEAN_UP: {
            future->result_dtor.clean_up(result_addr);
            break;
        } break;

        case AWS_FUTURE_T_POINTER_WITH_DESTROY: {
            void *result = *(void **)result_addr;
            if (result) {
                future->result_dtor.destroy(result);
            }
        } break;

        case AWS_FUTURE_T_POINTER_WITH_RELEASE: {
            void *result = *(void **)result_addr;
            if (result) {
                future->result_dtor.destroy(result);
            }
        } break;

        default:
            break;
    }
}

static void s_future_base_destroy(void *user_data) {
    struct aws_future_base *future = user_data;
    if (future->is_done && !future->error_code) {
        s_future_base_result_dtor(future, aws_future_base_get_result_address(future));
    }
    aws_condition_variable_clean_up(&future->wait_cvar);
    aws_mutex_clean_up(&future->lock);
    aws_mem_release(future->alloc, future);
}

static struct aws_future_base *s_future_base_new(struct aws_allocator *alloc, size_t result_size) {
    size_t total_size = sizeof(struct aws_future_base) + result_size;
    struct aws_future_base *future = aws_mem_calloc(alloc, 1, total_size);
    future->alloc = alloc;

    /* we store result_size in a bit field, ensure the number will fit */
    AWS_ASSERT(result_size <= (UINT_MAX >> (32 - AWS_FUTURE_RESULT_SIZE_BIT_COUNT)));
    future->result_size = (unsigned int)result_size;

    aws_ref_count_init(&future->ref_count, future, s_future_base_destroy);
    aws_mutex_init(&future->lock);
    aws_condition_variable_init(&future->wait_cvar);
    return future;
}

struct aws_future_base *aws_future_base_new_by_value(struct aws_allocator *alloc, size_t result_size) {
    struct aws_future_base *future = s_future_base_new(alloc, result_size);
    future->type = AWS_FUTURE_T_BY_VALUE;
    return future;
}

struct aws_future_base *aws_future_base_new_by_value_with_clean_up(
    struct aws_allocator *alloc,
    size_t result_size,
    aws_future_result_clean_up_fn *result_clean_up) {

    AWS_ASSERT(result_clean_up);
    struct aws_future_base *future = s_future_base_new(alloc, result_size);
    future->type = AWS_FUTURE_T_BY_VALUE_WITH_CLEAN_UP;
    future->result_dtor.clean_up = result_clean_up;
    return future;
}

struct aws_future_base *aws_future_base_new_pointer(struct aws_allocator *alloc) {
    struct aws_future_base *future = s_future_base_new(alloc, sizeof(void *));
    future->type = AWS_FUTURE_T_POINTER;
    return future;
}

struct aws_future_base *aws_future_base_new_pointer_with_destroy(
    struct aws_allocator *alloc,
    aws_future_result_destroy_fn *result_destroy) {

    AWS_ASSERT(result_destroy);
    struct aws_future_base *future = s_future_base_new(alloc, sizeof(void *));
    future->type = AWS_FUTURE_T_POINTER_WITH_DESTROY;
    future->result_dtor.destroy = result_destroy;
    return future;
}

struct aws_future_base *aws_future_base_new_pointer_with_release(
    struct aws_allocator *alloc,
    aws_future_result_release_fn *result_release) {

    AWS_ASSERT(result_release);
    struct aws_future_base *future = s_future_base_new(alloc, sizeof(void *));
    future->type = AWS_FUTURE_T_POINTER_WITH_RELEASE;
    future->result_dtor.release = result_release;
    return future;
}

struct aws_future_base *aws_future_base_release(struct aws_future_base *future) {
    if (future != NULL) {
        aws_ref_count_release(&future->ref_count);
    }
    return NULL;
}

struct aws_future_base *aws_future_base_acquire(struct aws_future_base *future) {
    if (future != NULL) {
        aws_ref_count_acquire(&future->ref_count);
    }
    return future;
}

bool aws_future_base_is_done(const struct aws_future_base *future) {
    AWS_ASSERT(future);

    /* this function is conceptually const, but we need to hold the lock a moment */
    struct aws_mutex *mutable_lock = (struct aws_mutex *)&future->lock;

    /* BEGIN CRITICAL SECTION */
    aws_mutex_lock(mutable_lock);
    bool is_done = future->is_done != 0;
    aws_mutex_unlock(mutable_lock);
    /* END CRITICAL SECTION */

    return is_done;
}

int aws_future_base_get_error(const struct aws_future_base *future) {
    AWS_ASSERT(future != NULL);
    /* not bothering with lock, none of this can change after future is done */
    AWS_FATAL_ASSERT(future->is_done && "Cannot get error before future is done");
    return future->error_code;
}

void *aws_future_base_get_result_address(const struct aws_future_base *future) {
    AWS_ASSERT(future != NULL);
    /* not bothering with lock, none of this can change after future is done */
    AWS_FATAL_ASSERT(future->is_done && "Cannot get result before future is done");
    AWS_FATAL_ASSERT(!future->error_code && "Cannot get result from future that failed with an error");

    const struct aws_future_base *address_of_memory_after_this_struct = future + 1;
    void *result_addr = (void *)address_of_memory_after_this_struct;
    return result_addr;
}

void *aws_future_base_get_result_as_pointer(const struct aws_future_base *future) {
    void *result_addr = aws_future_base_get_result_address(future);
    void **pointer_addr = result_addr;
    void *pointer = *pointer_addr;
    return pointer;
}

static void s_future_base_set_done(struct aws_future_base *future, void *src_address, int error_code) {
    bool is_error = error_code != 0;

    /* BEGIN CRITICAL SECTION */
    aws_mutex_lock(&future->lock);

    aws_future_base_on_done_fn *on_done_cb = future->on_done_cb;
    void *on_done_user_data = future->on_done_user_data;

    bool first_time = !future->is_done;
    if (first_time) {
        future->is_done = true;
        future->on_done_cb = NULL;
        future->on_done_user_data = NULL;
        if (is_error) {
            future->error_code = error_code;
        } else {
            memcpy(aws_future_base_get_result_address(future), src_address, future->result_size);
        }

        aws_condition_variable_notify_all(&future->wait_cvar);
    }

    aws_mutex_unlock(&future->lock);
    /* END CRITICAL SECTION */

    if (first_time) {
        /* invoke done callback outside critical section to avoid deadlock */
        if (on_done_cb) {
            on_done_cb(future, on_done_user_data);
        }
    } else if (!error_code) {
        /* future was already done, so just destroy this newer result */
        s_future_base_result_dtor(future, src_address);
    }
}

void aws_future_base_set_error(struct aws_future_base *future, int error_code) {
    AWS_ASSERT(future);

    /* handle recoverable usage error */
    AWS_ASSERT(error_code != 0);
    if (AWS_UNLIKELY(error_code == 0)) {
        error_code = AWS_ERROR_UNKNOWN;
    }

    s_future_base_set_done(future, NULL /*src_address*/, error_code);
}

void aws_future_base_set_result_by_memcpy(struct aws_future_base *future, void *src_address) {
    AWS_ASSERT(future);
    AWS_ASSERT(src_address);
    s_future_base_set_done(future, src_address, 0 /*error_code*/);
}

void aws_future_base_set_result_as_pointer(struct aws_future_base *future, void *pointer) {
    AWS_ASSERT(future);
    void *src_address = &pointer;
    s_future_base_set_done(future, src_address, 0 /*error_code*/);
}

void aws_future_base_register_callback(
    struct aws_future_base *future,
    aws_future_base_on_done_fn *on_done,
    void *user_data) {

    AWS_ASSERT(future);
    AWS_ASSERT(on_done);

    /* BEGIN CRITICAL SECTION */
    aws_mutex_lock(&future->lock);

    AWS_FATAL_ASSERT(future->on_done_cb == NULL && "Future done callback must only be set once");

    bool already_done = future->is_done != 0;

    /* if not done, store callback for later */
    if (!already_done) {
        future->on_done_cb = on_done;
        future->on_done_user_data = user_data;
    }

    aws_mutex_unlock(&future->lock);
    /* END CRITICAL SECTION */

    /* if already done, fire callback now */
    if (already_done) {
        on_done(future, user_data);
    }
}

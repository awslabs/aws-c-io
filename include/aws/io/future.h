#ifndef AWS_IO_FUTURE_H
#define AWS_IO_FUTURE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

AWS_PUSH_SANE_WARNING_LEVEL
#if defined(_MSC_VER)
#    pragma warning(disable : 5039) // reference to potentially throwing function passed to extern C function
#endif

struct aws_future_impl;

typedef void(aws_future_on_done_fn)(void *user_data);
typedef void(aws_future_destroy_result_fn)(void *);

typedef void(aws_future_result_clean_up_fn)(void *result_addr);
typedef void(aws_future_result_destroy_fn)(void *result);
typedef void *(aws_future_result_release_fn)(void *result);

AWS_EXTERN_C_BEGIN

/** Create future holding T by value, with no destructor */
AWS_IO_API
struct aws_future_impl *aws_future_impl_new_by_value(struct aws_allocator *alloc, size_t result_size);

/** Create future holding T by value, with destructor: void aws_T_clean_up(T*) */
AWS_IO_API
struct aws_future_impl *aws_future_impl_new_by_value_with_clean_up(
    struct aws_allocator *alloc,
    size_t result_size,
    aws_future_result_clean_up_fn *result_clean_up);

/** Create future holding T*, with no destructor */
AWS_IO_API
struct aws_future_impl *aws_future_impl_new_pointer(struct aws_allocator *alloc);

/** Create future holding T*, with destructor: void aws_T_destroy(T*) */
AWS_IO_API
struct aws_future_impl *aws_future_impl_new_pointer_with_destroy(
    struct aws_allocator *alloc,
    aws_future_result_destroy_fn *result_destroy);

/** Create future holding T*, with destructor: T* aws_T_release(T*) */
AWS_IO_API
struct aws_future_impl *aws_future_impl_new_pointer_with_release(
    struct aws_allocator *alloc,
    aws_future_result_release_fn *result_release);

AWS_IO_API
struct aws_future_impl *aws_future_impl_release(struct aws_future_impl *promise);

AWS_IO_API
struct aws_future_impl *aws_future_impl_acquire(struct aws_future_impl *promise);

/**
 * Set future as done, with an error_code.
 * If the future is already done, this call is ignored.
 */
AWS_IO_API
void aws_future_impl_set_error(struct aws_future_impl *promise, int error_code);

/**
 * Set the future as done, with a valid result.
 *
 * Ownership of the result is transferred to the future. The value at src_address
 * is memcpy'd into the future, and then zeroed out.
 *
 * It is safe to set the result multiple times. If the future is already done,
 * the new result is destroyed instead of saved.
 *
 * WARNING: src_address MUST NOT be NULL.
 */
AWS_IO_API
void aws_future_impl_set_result(struct aws_future_impl *promise, void *src_address);

/**
 * Return whether the future is done.
 */
AWS_IO_API
bool aws_future_impl_is_done(const struct aws_future_impl *future);

/**
 * Register completion callback to be invoked as soon as possible.
 *
 * If the future is already done, the callback runs immediately on the calling thread.
 * If the future completes after the callback is registered, the callback
 * will run on whatever thread completes the future.
 *
 * WARNING: You MUST NOT register more than one callback.
 */
AWS_IO_API
void aws_future_impl_register_callback(struct aws_future_impl *future, aws_future_on_done_fn *on_done, void *user_data);

/**
 * If the future isn't done yet, then register the completion callback.
 *
 * Returns true if the callback was registered, or false if the callback
 * is already complete.
 *
 * Use this when you can't risk the callback running immediately.
 * For example: If you're calling an async function repeatedly,
 * and synchronous completion could lead to stack overflow due to recursion.
 * Or if you are holding a non-recursive mutex, and the callback also
 * needs the mutex, and an immediate callback would deadlock.
 *
 * WARNING: If a callback is registered, you MUST NOT call this again until
 * after the callback has been invoked.
 */
AWS_IO_API
bool aws_future_impl_register_callback_if_not_done(
    struct aws_future_impl *future,
    aws_future_on_done_fn *on_done,
    void *user_data);

/**
 * Wait (up to timeout_ns) for future to complete.
 * Returns true if future completes in this time.
 * This blocks the current thread, and is probably only useful for tests and sample programs.
 */
AWS_IO_API
bool aws_future_impl_wait(const struct aws_future_impl *future, uint64_t timeout_ns);

/**
 * Get the error-code of a completed future.
 * If it returns 0 then the future completed successfully,
 * you may now call get_result().
 *
 * WARNING: You MUST NOT call this until the future is done.
 */
AWS_IO_API
int aws_future_impl_get_error(const struct aws_future_impl *future);

/**
 * Take ownership of a complete future's result (for result T stored by value).
 *
 * The result is memcpy'd to dst_address.
 * You are now responsible for cleaning it up, the future no longer owns it.
 *
 * WARNING 1: You MUST NOT call this until the future is done.
 * WARNING 2: You MUST NOT call this unless get_error() returned 0.
 * WARNING 3: You MUST NOT call this multiple times.
 */
AWS_IO_API
void aws_future_impl_get_result_by_value(struct aws_future_impl *future, void *dst_address);

/**
 * Take ownership of a complete future's result (for result T stored as pointer).
 *
 * The result is memcpy'd to dst_address.
 * You are now responsible for cleaning it up, the future no longer owns it.
 *
 * WARNING 1: You MUST NOT call this until the future is done.
 * WARNING 2: You MUST NOT call this unless get_error() returned 0.
 * WARNING 3: You MUST NOT call this multiple times.
 */
AWS_IO_API
void *aws_future_impl_get_result_as_pointer(struct aws_future_impl *future);

#define AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE) struct FUTURE;

#define AWS_FUTURE_T_DECLARATION_END(FUTURE)                                                                           \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_acquire(struct FUTURE *future) {                                           \
        return (struct FUTURE *)aws_future_impl_acquire((struct aws_future_impl *)future);                             \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_release(struct FUTURE *future) {                                           \
        return (struct FUTURE *)aws_future_impl_release((struct aws_future_impl *)future);                             \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_error(struct FUTURE *future, int error_code) {                                   \
        aws_future_impl_set_error((struct aws_future_impl *)future, error_code);                                       \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL bool FUTURE##_is_done(const struct FUTURE *future) {                                               \
        return aws_future_impl_is_done((const struct aws_future_impl *)future);                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL int FUTURE##_get_error(const struct FUTURE *future) {                                              \
        return aws_future_impl_get_error((const struct aws_future_impl *)future);                                      \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL                                                                                                    \
    void FUTURE##_register_callback(struct FUTURE *future, aws_future_on_done_fn *on_done, void *user_data) {          \
        aws_future_impl_register_callback((struct aws_future_impl *)future, on_done, user_data);                       \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL                                                                                                    \
    bool FUTURE##_register_callback_if_not_done(                                                                       \
        struct FUTURE *future, aws_future_on_done_fn *on_done, void *user_data) {                                      \
        return aws_future_impl_register_callback_if_not_done((struct aws_future_impl *)future, on_done, user_data);    \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL                                                                                                    \
    bool FUTURE##_wait(struct FUTURE *future, uint64_t timeout_ns) {                                                   \
        return aws_future_impl_wait((struct aws_future_impl *)future, timeout_ns);                                     \
    }

/**
 * Declare a future that holds a simple T by value, that needs no destructor.
 * Use with types like bool, size_t, etc.
 */
#define AWS_DECLARE_FUTURE_T_BY_VALUE(FUTURE, T)                                                                       \
    AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                             \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_new(struct aws_allocator *alloc) {                                         \
        return (struct FUTURE *)aws_future_impl_new_by_value(alloc, sizeof(T));                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T result) {                                        \
        aws_future_impl_set_result((struct aws_future_impl *)future, &result);                                         \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T FUTURE##_get_result(struct FUTURE *future) {                                                     \
        T value;                                                                                                       \
        aws_future_impl_get_result_by_value((struct aws_future_impl *)future, &value);                                 \
        return value;                                                                                                  \
    }                                                                                                                  \
                                                                                                                       \
    AWS_FUTURE_T_DECLARATION_END(FUTURE)

#if 0 /* TODO */
/**
 * Declares a future that holds T by value, with destructor like: void aws_T_clean_up(T*)
 * Use with types like aws_byte_buf.
 */
#    define AWS_DECLARE_FUTURE_T_BY_VALUE_WITH_CLEAN_UP(FUTURE, T, CLEAN_UP_FN)
#endif /* TODO */

/**
 * Declares a future that holds T*, with no destructor.
 */
#define AWS_DECLARE_FUTURE_T_POINTER(FUTURE, T)                                                                        \
    AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                             \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_new(struct aws_allocator *alloc) {                                         \
        return (struct FUTURE *)aws_future_impl_new_pointer(alloc);                                                    \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T **result) {                                      \
        aws_future_impl_set_result((struct aws_future_impl *)future, result);                                          \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T *FUTURE##_get_result(struct FUTURE *future) {                                                    \
        return aws_future_impl_get_result_as_pointer((struct aws_future_impl *)future);                                \
    }                                                                                                                  \
                                                                                                                       \
    AWS_FUTURE_T_DECLARATION_END(FUTURE)

/**
 * Declares a future that holds T*, with destructor like: void aws_T_destroy(T*)
 * Use with types like aws_string.
 */
#define AWS_DECLARE_FUTURE_T_POINTER_WITH_DESTROY(FUTURE, T, DESTROY_FN)                                               \
    AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                             \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_new(struct aws_allocator *alloc) {                                         \
        void (*destroy_fn)(T *) = DESTROY_FN; /* check destroy() function signature */                                 \
        return (struct FUTURE *)aws_future_impl_new_pointer_with_destroy(                                              \
            alloc, (aws_future_result_destroy_fn *)destroy_fn);                                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T **result) {                                      \
        aws_future_impl_set_result((struct aws_future_impl *)future, result);                                          \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T *FUTURE##_get_result(struct FUTURE *future) {                                                    \
        return aws_future_impl_get_result_as_pointer((struct aws_future_impl *)future);                                \
    }                                                                                                                  \
                                                                                                                       \
    AWS_FUTURE_T_DECLARATION_END(FUTURE)

/**
 * Declares a future that holds T*, with destructor like: T* aws_T_release(T*)
 * Use with types like aws_http_message
 */
#define AWS_DECLARE_FUTURE_T_POINTER_WITH_RELEASE(FUTURE, T, RELEASE_FN)                                               \
    AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                             \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_new(struct aws_allocator *alloc) {                                         \
        T *(*release_fn)(T *) = RELEASE_FN; /* check release() function signature */                                   \
        return (struct FUTURE *)aws_future_impl_new_pointer_with_release(                                              \
            alloc, (aws_future_result_release_fn *)release_fn);                                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T **result) {                                      \
        aws_future_impl_set_result((struct aws_future_impl *)future, result);                                          \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T *FUTURE##_get_result(struct FUTURE *future) {                                                    \
        return aws_future_impl_get_result_as_pointer((struct aws_future_impl *)future);                                \
    }                                                                                                                  \
                                                                                                                       \
    AWS_FUTURE_T_DECLARATION_END(FUTURE)

/**
 * aws_future<size_t>
 */
AWS_DECLARE_FUTURE_T_BY_VALUE(aws_future_size, size_t)

/**
 * aws_future<bool>
 */
AWS_DECLARE_FUTURE_T_BY_VALUE(aws_future_bool, bool)

/**
 * aws_future<void>
 */
AWS_FUTURE_T_DECLARATION_BEGIN(aws_future_void)

AWS_STATIC_IMPL struct aws_future_void *aws_future_void_new(struct aws_allocator *alloc) {
    /* Use aws_future<bool> under the hood, to avoid edge-cases with 0-sized result */
    return (struct aws_future_void *)aws_future_bool_new(alloc);
}

AWS_STATIC_IMPL void aws_future_void_set_result(struct aws_future_void *future) {
    aws_future_bool_set_result((struct aws_future_bool *)future, false);
}

AWS_FUTURE_T_DECLARATION_END(aws_future_void)

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_IO_FUTURE_H */

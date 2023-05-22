#ifndef AWS_IO_FUTURE_H
#define AWS_IO_FUTURE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>

AWS_PUSH_SANE_WARNING_LEVEL
#if defined(_MSC_VER)
#    pragma warning(disable : 5039) // reference to potentially throwing function passed to extern C function
#endif

struct aws_future_base;

typedef void(aws_future_base_on_done_fn)(struct aws_future_base *future, void *user_data);
typedef void(aws_future_destroy_result_fn)(void *);

typedef void(aws_future_result_clean_up_fn)(void *result_addr);
typedef void(aws_future_result_destroy_fn)(void *result);
typedef void *(aws_future_result_release_fn)(void *result);

enum aws_future_type {
    /** Future holding T by value, with no destructor */
    AWS_FUTURE_T_BY_VALUE,
    /** Future holding T by value, with destructor: void aws_T_clean_up(T*) */
    AWS_FUTURE_T_BY_VALUE_WITH_CLEAN_UP,
    /** Future holding T*, with no destructor */
    AWS_FUTURE_T_POINTER,
    /** Future holding T*, with destructor: void aws_T_destroy(T*) */
    AWS_FUTURE_T_POINTER_WITH_DESTROY,
    /** Future holding T*, with destructor: T* aws_T_release(T*) */
    AWS_FUTURE_T_POINTER_WITH_RELEASE,
};

struct aws_future_base {
    struct aws_allocator *alloc;
    struct aws_ref_count ref_count;
    struct aws_mutex lock;
    struct aws_condition_variable wait_cvar;
    aws_future_base_on_done_fn *on_done_cb;
    void *on_done_user_data;
    union {
        aws_future_result_clean_up_fn *clean_up;
        aws_future_result_destroy_fn *destroy;
        aws_future_result_release_fn *release;
    } result_dtor;
    int error_code;
    /* sum of bit fields should be 32 */
#define AWS_FUTURE_RESULT_SIZE_BIT_COUNT 28
    unsigned int result_size : AWS_FUTURE_RESULT_SIZE_BIT_COUNT;
    unsigned int type : 3; /* aws_future_type */
    unsigned int is_done : 1;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API
struct aws_future_base *aws_future_base_new_by_value(struct aws_allocator *alloc, size_t result_size);

AWS_IO_API
struct aws_future_base *aws_future_base_new_by_value_with_clean_up(
    struct aws_allocator *alloc,
    size_t result_size,
    aws_future_result_clean_up_fn *result_clean_up);

AWS_IO_API
struct aws_future_base *aws_future_base_new_pointer(struct aws_allocator *alloc);

AWS_IO_API
struct aws_future_base *aws_future_base_new_pointer_with_destroy(
    struct aws_allocator *alloc,
    aws_future_result_destroy_fn *result_destroy);

AWS_IO_API
struct aws_future_base *aws_future_base_new_pointer_with_release(
    struct aws_allocator *alloc,
    aws_future_result_release_fn *result_release);

AWS_IO_API
struct aws_future_base *aws_future_base_release(struct aws_future_base *future);

AWS_IO_API
struct aws_future_base *aws_future_base_acquire(struct aws_future_base *future);

AWS_IO_API
void aws_future_base_set_error(struct aws_future_base *future, int error_code);

AWS_IO_API
bool aws_future_base_is_done(const struct aws_future_base *future);

AWS_IO_API
void aws_future_base_register_callback(
    struct aws_future_base *future,
    aws_future_base_on_done_fn *on_done,
    void *user_data);

AWS_IO_API
bool aws_future_base_register_callback_if_not_done(
    struct aws_future_base *future,
    aws_future_base_on_done_fn *on_done,
    void *user_data);

AWS_IO_API
bool aws_future_base_wait(const struct aws_future_base *future, uint64_t duration_ns);

AWS_IO_API
int aws_future_base_get_error(const struct aws_future_base *future);

AWS_IO_API
void *aws_future_base_get_result_address(const struct aws_future_base *future);

AWS_IO_API
void *aws_future_base_get_result_as_pointer(const struct aws_future_base *future);

AWS_IO_API
void aws_future_base_set_result_by_memcpy(struct aws_future_base *future, void *src_address);

AWS_IO_API
void aws_future_base_set_result_as_pointer(struct aws_future_base *future, void *pointer);

#define AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                         \
    struct FUTURE;                                                                                                     \
    typedef void(FUTURE##_on_done_fn)(struct FUTURE * future, void *user_data);

#define AWS_FUTURE_T_DECLARATION_END(FUTURE)                                                                           \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_acquire(struct FUTURE *future) {                                           \
        return (struct FUTURE *)aws_future_base_acquire((struct aws_future_base *)future);                             \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_release(struct FUTURE *future) {                                           \
        return (struct FUTURE *)aws_future_base_release((struct aws_future_base *)future);                             \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_error(struct FUTURE *future, int error_code) {                                   \
        aws_future_base_set_error((struct aws_future_base *)future, error_code);                                       \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL bool FUTURE##_is_done(const struct FUTURE *future) {                                               \
        return aws_future_base_is_done((const struct aws_future_base *)future);                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL int FUTURE##_get_error(const struct FUTURE *future) {                                              \
        return aws_future_base_get_error((const struct aws_future_base *)future);                                      \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL                                                                                                    \
    void FUTURE##_register_callback(struct FUTURE *future, FUTURE##_on_done_fn *on_done, void *user_data) {            \
        aws_future_base_register_callback(                                                                             \
            (struct aws_future_base *)future, (aws_future_base_on_done_fn *)on_done, user_data);                       \
    }

/**
 * Declare a future that holds a simple T by value, that needs no destructor.
 * Use with types like bool, size_t, etc.
 */
#define AWS_DECLARE_FUTURE_T_BY_VALUE(FUTURE, T)                                                                       \
    AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                             \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_new(struct aws_allocator *alloc) {                                         \
        return (struct FUTURE *)aws_future_base_new_by_value(alloc, sizeof(T));                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T result) {                                        \
        aws_future_base_set_result_by_memcpy((struct aws_future_base *)future, &result);                               \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T FUTURE##_get_result(const struct FUTURE *future) {                                               \
        return *(T *)aws_future_base_get_result_address((const struct aws_future_base *)future);                       \
    }                                                                                                                  \
                                                                                                                       \
    AWS_FUTURE_T_DECLARATION_END(FUTURE)

/**
 * Declares a future that holds T by value, with destructor like: void aws_T_clean_up(T*)
 * Use with types like aws_byte_buf.
 */
#define AWS_DECLARE_FUTURE_T_BY_VALUE_WITH_CLEAN_UP(FUTURE, T, CLEAN_UP_FN)

/**
 * Declares a future that holds T*, with no destructor.
 */
#define AWS_DECLARE_FUTURE_T_POINTER(FUTURE, T)

/**
 * Declares a future that holds T*, with destructor like: void aws_T_destroy(T*)
 * Use with types like aws_string.
 */
#define AWS_DECLARE_FUTURE_T_POINTER_WITH_DESTROY(FUTURE, T, DESTROY_FN)                                               \
    AWS_FUTURE_T_DECLARATION_BEGIN(FUTURE)                                                                             \
                                                                                                                       \
    AWS_STATIC_IMPL struct FUTURE *FUTURE##_new(struct aws_allocator *alloc) {                                         \
        void (*destroy_fn)(T *) = DESTROY_FN; /* check destroy() function signature */                                 \
        return (struct FUTURE *)aws_future_base_new_pointer_with_destroy(                                              \
            alloc, (aws_future_result_destroy_fn *)destroy_fn);                                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T *result) {                                       \
        aws_future_base_set_result_as_pointer((struct aws_future_base *)future, result);                               \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T *FUTURE##_get_result(const struct FUTURE *future) {                                              \
        return aws_future_base_get_result_as_pointer((const struct aws_future_base *)future);                          \
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
        return (struct FUTURE *)aws_future_base_new_pointer_with_release(                                              \
            alloc, (aws_future_result_release_fn *)release_fn);                                                        \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL void FUTURE##_set_result(struct FUTURE *future, T *result) {                                       \
        aws_future_base_set_result_as_pointer((struct aws_future_base *)future, result);                               \
    }                                                                                                                  \
                                                                                                                       \
    AWS_STATIC_IMPL T *FUTURE##_get_result(const struct FUTURE *future) {                                              \
        return aws_future_base_get_result_as_pointer((const struct aws_future_base *)future);                          \
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

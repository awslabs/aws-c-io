#ifndef AWS_IO_CLIENT_RETRY_STRATEGY_H
#define AWS_IO_CLIENT_RETRY_STRATEGY_H
/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/io/event_loop.h>

#include <aws/common/atomics.h>

struct aws_retry_strategy;
struct aws_retry_token;

/**
 * Invoked upon the acquisition, or failure to acquire a retry token. This function will always be invoked if and only
 * if aws_retry_strategy_acquire_retry_token() returns AWS_OP_SUCCESS. It will never be invoked synchronously from
 * aws_retry_strategy_acquire_retry_token().
 */
typedef void(aws_retry_strategy_on_retry_token_acquired_fn)(
    struct aws_retry_strategy *retry_strategy,
    int error_code,
    struct aws_retry_token *token,
    void *user_data);

/**
 * Invoked after a successful call to aws_retry_strategy_schedule_retry(). This function will always be invoked if and
 * only if aws_retry_strategy_schedule_retry() returns AWS_OP_SUCCESS. It will never be invoked synchronously from
 * aws_retry_strategy_schedule_retry().
 */
typedef void(aws_retry_strategy_on_retry_ready_fn)(struct aws_retry_token *token, int error_code, void *user_data);

enum aws_retry_error_type {
    /** This is a connection level error such as a socket timeout, socket connect error, tls negotiation timeout etc...
     * Typically these should never be applied for non-idempotent request types. */
    AWS_RETRY_ERROR_TYPE_TRANSIENT,
    /** This is an error where the server explicitly told the client to back off, such as a 429 or 503 Http error. */
    AWS_RETRY_ERROR_TYPE_THROTTLING,
    /** This is a server error that isn't explicitly throttling but is considered by the client
     * to be something that should be retried. */
    AWS_RETRY_ERROR_TYPE_SERVER_ERROR,
    /** Doesn't count against any budgets. This could be something like a 401 challenge in Http. */
    AWS_RETRY_ERROR_TYPE_CLIENT_ERROR,
};

struct aws_retry_strategy_vtable {
    void (*destroy)(struct aws_retry_strategy *retry_strategy);
    int (*acquire_token)(
        struct aws_retry_strategy *retry_strategy,
        const struct aws_byte_cursor *partition_id,
        aws_retry_strategy_on_retry_token_acquired_fn *on_acquired,
        void *user_data,
        uint64_t timeout_ms);
    int (*schedule_retry)(
        struct aws_retry_token *token,
        enum aws_retry_error_type error_type,
        aws_retry_strategy_on_retry_ready_fn *retry_ready,
        void *user_data);
    int (*record_success)(struct aws_retry_token *token);
    void (*release_token)(struct aws_retry_token *token);
};

struct aws_retry_strategy {
    struct aws_allocator *allocator;
    struct aws_retry_strategy_vtable *vtable;
    struct aws_atomic_var ref_count;
    void *impl;
};

struct aws_retry_token {
    struct aws_allocator *allocator;
    struct aws_retry_strategy *retry_strategy;
    void *impl;
};

/**
 * Jitter mode for exponential backoff.
 *
 * For a great writeup on these options see:
 * https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
 */
enum aws_exponential_backoff_jitter_mode {
    AWS_EXPONENTIAL_BACKOFF_JITTER_NONE,
    AWS_EXPONENTIAL_BACKOFF_JITTER_FULL,
    AWS_EXPONENTIAL_BACKOFF_JITTER_DECORRELATED,
    /* Uses AWS_EXPONENTIAL_BACKOFF_JITTER_FULL */
    AWS_EXPONENTIAL_BACKOFF_JITTER_DEFAULT,
};

struct aws_exponential_backoff_retry_config {
    /** Event loop group to use for scheduling tasks. */
    struct aws_event_loop_group *el_group;
    /** Max retries to allow. This value must be greater than 0 */
    size_t max_retries;
    /** Scaling factor to add for the backoff. 25ms is usually a good default. */
    uint32_t backoff_scale_factor_ms;
    /** Jitter mode to use, see comments for aws_exponential_backoff_jitter_mode. */
    enum aws_exponential_backoff_jitter_mode jitter_mode;
    /** By default this will be set to use aws_device_random. If you want something else, set it here. */
    uint64_t (*generate_random)(void);
};

/**
 * Defaults to 10 retries, 25ms scaling factor, and full jitter.
 */
#define AWS_EXPONENTIAL_BACKOFF_DEFAULT_CONFIG(el_group)                                                               \
    /* Don't do this with designated initializers, otherwise C++ users can't touch this. */                            \
    { el_group, 10, 25, AWS_EXPONENTIAL_BACKOFF_JITTER_FULL, }

AWS_EXTERN_C_BEGIN
/**
 * Acquire a reference count on retry_strategy.
 */
AWS_IO_API void aws_retry_strategy_acquire(struct aws_retry_strategy *retry_strategy);
/**
 * Releases a reference count on retry_strategy.
 */
AWS_IO_API void aws_retry_strategy_release(struct aws_retry_strategy *retry_strategy);
/**
 * Attempts to acquire a retry token for use with retries. On success, on_acquired will be invoked when a token is
 * available, or an error will be returned if the timeout expires. partition_id identifies operations that should be
 * grouped together. This allows for more sophisticated strategies such as AIMD and circuit breaker patterns. Pass NULL
 * to use the global partition.
 */
AWS_IO_API int aws_retry_strategy_acquire_retry_token(
    struct aws_retry_strategy *retry_strategy,
    const struct aws_byte_cursor *partition_id,
    aws_retry_strategy_on_retry_token_acquired_fn *on_acquired,
    void *user_data,
    uint64_t timeout_ms);
/**
 * Schedules a retry based on the backoff and token based strategies. retry_ready is invoked when the retry is either
 * ready for execution or if it has been canceled due to application shutdown.
 *
 * This function can return an error to reject the retry attempt if, for example, a circuit breaker has opened. If this
 * occurs users should fail their calls back to their callers.
 *
 * error_type is used for book keeping. See the comments above for aws_retry_error_type.
 */
AWS_IO_API int aws_retry_strategy_schedule_retry(
    struct aws_retry_token *token,
    enum aws_retry_error_type error_type,
    aws_retry_strategy_on_retry_ready_fn *retry_ready,
    void *user_data);
/**
 * Records a successful retry. This is used for making future decisions to open up token buckets, AIMD breakers etc...
 * some strategies such as exponential backoff will ignore this, but you should always call it after a successful
 * operation or your system will never recover during an outage.
 */
AWS_IO_API int aws_retry_strategy_token_record_success(struct aws_retry_token *token);
/**
 * Releases the reference count for token. This should always be invoked after either calling
 * aws_retry_strategy_schedule_retry() and failing, or after calling aws_retry_strategy_token_record_success().
 */
AWS_IO_API void aws_retry_strategy_release_retry_token(struct aws_retry_token *token);
/**
 * Creates a retry strategy using exponential backoff. This strategy does not perform any bookkeeping on error types and
 * success. There is no circuit breaker functionality in here. See the comments above for
 * aws_exponential_backoff_retry_config.
 */
AWS_IO_API struct aws_retry_strategy *aws_retry_strategy_new_exponential_backoff(
    struct aws_allocator *allocator,
    const struct aws_exponential_backoff_retry_config *config);
AWS_EXTERN_C_END

#endif /* AWS_IO_CLIENT_RETRY_STRATEGY_H */

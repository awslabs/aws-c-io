#ifndef AWS_IO_URI_H
#define AWS_IO_URI_H
/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/io/io.h>

#include <aws/common/byte_buf.h>

/**
 * Data representing a URI. uri_str is always allocated and filled in.
 * The other portions are merely storing offsets into uri_str.
 */
struct aws_uri {
    size_t self_size;
    struct aws_allocator *allocator;
    struct aws_byte_buf uri_str;
    struct aws_byte_cursor scheme;
    struct aws_byte_cursor authority;
    struct aws_byte_cursor host_name;
    uint16_t port;
    struct aws_byte_cursor path;
    struct aws_byte_cursor query_string;
    struct aws_byte_cursor path_and_query;
};

/**
 * key/value pairs for a query string. If the query fragment was not in format key=value, the fragment value
 * will be stored in key
 */
struct aws_uri_param {
    struct aws_byte_cursor key;
    struct aws_byte_cursor value;
};

/**
 * Arguments for building a URI instance. All members must
 * be initialized before passing them to aws_uri_init().
 *
 * query_string and query_params are exclusive to each other. If you set
 * query_string, do not prepend it with '?'
 */
struct aws_uri_builder_options {
    struct aws_byte_cursor scheme;
    struct aws_byte_cursor path;
    struct aws_byte_cursor host_name;
    uint16_t port;
    struct aws_array_list *query_params;
    struct aws_byte_cursor query_string;
};

AWS_EXTERN_C_BEGIN

/**
 * Parses 'uri_str' and initializes uri. Returns AWS_OP_SUCCESS, on success, AWS_OP_ERR on failure.
 * After calling this function, the parts can be accessed.
 */
AWS_IO_API int aws_uri_init_parse(
    struct aws_uri *uri,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *uri_str);

/**
 * Initializes uri to values specified in options. Returns AWS_OP_SUCCESS, on success, AWS_OP_ERR on failure.
 * After calling this function, the parts can be accessed.
 */
AWS_IO_API int aws_uri_init_from_builder_options(
    struct aws_uri *uri,
    struct aws_allocator *allocator,
    struct aws_uri_builder_options *options);
AWS_IO_API void aws_uri_clean_up(struct aws_uri *uri);

/**
 * Returns the scheme portion of the uri (e.g. http, https, ftp, ftps, etc...). If the scheme was not present
 * in the uri, the returned value will be empty. It is the users job to determine the appropriate defaults
 * if this field is empty, based on protocol, port, etc...
 */
AWS_IO_API const struct aws_byte_cursor *aws_uri_scheme(const struct aws_uri *uri);

/**
 * Returns the authority portion of the uri (host[:port]). If it was not present, this was a request uri. In that
 * case, the value will be empty.
 */
AWS_IO_API const struct aws_byte_cursor *aws_uri_authority(const struct aws_uri *uri);

/**
 * Returns the path portion of the uri. If the original value was empty, this value will be "/".
 */
AWS_IO_API const struct aws_byte_cursor *aws_uri_path(const struct aws_uri *uri);

/**
 * Returns the query string portion of the uri, minus the '?'. If not present, this value will be empty.
 */
AWS_IO_API const struct aws_byte_cursor *aws_uri_query_string(const struct aws_uri *uri);

/**
 * Returns the 'host_name' portion of the authority. If no authority was present, this value will be empty.
 */
AWS_IO_API const struct aws_byte_cursor *aws_uri_host_name(const struct aws_uri *uri);

/**
 * Returns the port portion of the authority if it was present, otherwise, returns 0.
 * If this is 0, it is the users job to determine the correct port based on scheme and protocol.
 */
AWS_IO_API uint16_t aws_uri_port(const struct aws_uri *uri);

/**
 * Returns the path and query portion of the uri (i.e., the thing you send accross the wire).
 */
AWS_IO_API const struct aws_byte_cursor *aws_uri_path_and_query(const struct aws_uri *uri);

/**
 * Parses query string and stores the parameters in 'out_params'. Returns AWS_OP_SUCCESS on success and
 * AWS_OP_ERR on failure. The user is responsible for initializing out_params with item size of struct aws_query_param.
 * The user is also responsible for cleaning up out_params when finished.
 */
AWS_IO_API int aws_uri_query_string_params(const struct aws_uri *uri, struct aws_array_list *out_params);

AWS_EXTERN_C_END

#endif /* AWS_IO_URI_H */

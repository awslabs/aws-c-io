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
#include <aws/io/uri.h>

#include <aws/common/common.h>

#include <string.h>


enum parser_state {
    ON_SCHEME,
    ON_AUTHORITY,
    ON_PATH,
    ON_QUERY_STRING,
    FINISHED,
    ERROR,
};

struct uri_parser {
    struct aws_uri *uri;
    enum parser_state state;
};

typedef void(parse_fn)(struct uri_parser *parser, struct aws_byte_cursor *str);

static void s_parse_scheme(struct uri_parser *parser, struct aws_byte_cursor *str);
static void s_parse_authority(struct uri_parser *parser, struct aws_byte_cursor *str);
static void s_parse_path(struct uri_parser *parser, struct aws_byte_cursor *str);
static void s_parse_query_string(struct uri_parser *parser, struct aws_byte_cursor *str);


static parse_fn *s_states[] = {
        [ON_SCHEME] = s_parse_scheme,
        [ON_AUTHORITY] = s_parse_authority,
        [ON_PATH] = s_parse_path,
        [ON_QUERY_STRING] = s_parse_query_string,
};

int aws_uri_init_parse(struct aws_uri *uri, struct aws_allocator *allocator, const struct aws_byte_cursor *uri_str) {
    AWS_ZERO_STRUCT(*uri);
    uri->allocator = allocator;

    if (aws_byte_buf_init_copy_from_cursor(&uri->uri_str, allocator, *uri_str)) {
        return AWS_OP_ERR;
    }

    struct uri_parser parser = {
            .state = ON_SCHEME,
            .uri = uri,
    };

    struct aws_byte_cursor uri_cur = aws_byte_cursor_from_buf(&uri->uri_str);

    while (parser.state < FINISHED) {
        s_states[parser.state](&parser, &uri_cur);
    }

    return parser.state == FINISHED ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

int aws_uri_init(struct aws_uri *uri, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*uri);
    uri->allocator = allocator;
    return AWS_OP_SUCCESS;
}

void aws_uri_clean_up(struct aws_uri *uri) {
    if (uri->uri_str.allocator) {
        aws_byte_buf_clean_up(&uri->uri_str);
    }
    AWS_ZERO_STRUCT(*uri);
}

const struct aws_byte_cursor *aws_uri_scheme(const struct aws_uri *uri) {
    return &uri->scheme;
}

const struct aws_byte_cursor *aws_uri_authority(const struct aws_uri *uri){
    return &uri->authority;
}

const struct aws_byte_cursor *aws_uri_path(const struct aws_uri *uri) {
    return &uri->path;
}

const struct aws_byte_cursor *aws_uri_query_string(const struct aws_uri *uri) {
    return &uri->query_string;
}

static const char *s_default_scheme = "https";

static void s_parse_scheme(struct uri_parser *parser, struct aws_byte_cursor *str) {
    uint8_t *location_of_colon = memchr(str, ':', str->len);

    if (!location_of_colon) {
        parser->uri->scheme = aws_byte_cursor_from_c_str(s_default_scheme);
        parser->state = ON_AUTHORITY;
        return;
    }

    parser->uri->scheme.ptr = str->ptr,
    parser->uri->scheme.len = location_of_colon - str->ptr - 1;

    aws_byte_cursor_advance(str, parser->uri->scheme.len);

    if (str->len < 3 || str->ptr[0] != ':' || str->ptr[1] != '/' || str->ptr[2] != '/') {
        aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
        parser->state = ERROR;
        return;
    }

    aws_byte_cursor_advance(str, 3);
    parser->state = ON_AUTHORITY;
}

static const char *s_default_path = "/";

static void s_parse_authority(struct uri_parser *parser, struct aws_byte_cursor *str) {
    uint8_t *location_of_slash = memchr(str, '/', str->len);

    if (!location_of_slash && str->len) {
        parser->uri->authority.ptr = str->ptr;
        parser->uri->authority.len = str->len;

        parser->uri->path.ptr = (uint8_t *)s_default_path;
        parser->uri->path.len = 1;

        parser->state = FINISHED;
        aws_byte_cursor_advance(str, parser->uri->authority.len);
        return;
    }

    if (!str->len) {
        parser->state = ERROR;
        aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
        return;
    }

    parser->uri->authority.ptr = str->ptr;
    parser->uri->authority.len = location_of_slash - str->ptr - 1;

    aws_byte_cursor_advance(str, parser->uri->authority.len + 1);
    parser->state = ON_PATH;
}

static void s_parse_path(struct uri_parser *parser, struct aws_byte_cursor *str) {
    uint8_t *location_of_q_mark = memchr(str, '?', str->len);

    if (!location_of_q_mark) {
        parser->uri->path = (struct aws_byte_cursor){
                .ptr = str->ptr,
                .len = str->len,
        };

        parser->state = FINISHED;
        aws_byte_cursor_advance(str, parser->uri->path.len);
        return;
    }

    if (!str->len) {
        parser->state = ERROR;
        aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
        return;
    }

    parser->uri->path.ptr = str->ptr;
    parser->uri->path.len = location_of_q_mark - str->ptr - 1;
    aws_byte_cursor_advance(str, parser->uri->path.len + 1);
    parser->state = ON_QUERY_STRING;
}

static void s_parse_query_string(struct uri_parser *parser, struct aws_byte_cursor *str) {
    /* we don't want the '?' character. */
    if (str->len) {
        parser->uri->query_string.ptr = str->ptr + 1;
        parser->uri->query_string.len = str->len - 1;
    }

    aws_byte_cursor_advance(str, parser->uri->query_string.len + 1);
    parser->state = FINISHED;
}


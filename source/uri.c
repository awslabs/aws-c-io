/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/uri.h>

#include <aws/common/common.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#if _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#    pragma warning(disable : 4996) /* sprintf */
#endif

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

static int s_init_from_uri_str(struct aws_uri *uri) {
    struct uri_parser parser = {
        .state = ON_SCHEME,
        .uri = uri,
    };

    struct aws_byte_cursor uri_cur = aws_byte_cursor_from_buf(&uri->uri_str);

    while (parser.state < FINISHED) {
        s_states[parser.state](&parser, &uri_cur);
    }

    /* Each state function sets the next state, if something goes wrong it sets it to ERROR which is > FINISHED */
    if (parser.state == FINISHED) {
        return AWS_OP_SUCCESS;
    }

    aws_byte_buf_clean_up(&uri->uri_str);
    AWS_ZERO_STRUCT(*uri);
    return AWS_OP_ERR;
}

int aws_uri_init_parse(struct aws_uri *uri, struct aws_allocator *allocator, const struct aws_byte_cursor *uri_str) {
    AWS_ZERO_STRUCT(*uri);
    uri->self_size = sizeof(struct aws_uri);
    uri->allocator = allocator;

    if (aws_byte_buf_init_copy_from_cursor(&uri->uri_str, allocator, *uri_str)) {
        return AWS_OP_ERR;
    }

    return s_init_from_uri_str(uri);
}

int aws_uri_init_from_builder_options(
    struct aws_uri *uri,
    struct aws_allocator *allocator,
    struct aws_uri_builder_options *options) {

    AWS_ZERO_STRUCT(*uri);

    if (options->query_string.len && options->query_params) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    uri->self_size = sizeof(struct aws_uri);
    uri->allocator = allocator;

    size_t buffer_size = 0;
    if (options->scheme.len) {
        /* 3 for :// */
        buffer_size += options->scheme.len + 3;
    }

    buffer_size += options->host_name.len;

    if (options->port) {
        /* max strlen of a 16 bit integer is 5 */
        buffer_size += 6;
    }

    buffer_size += options->path.len;

    if (options->query_params) {
        size_t query_len = aws_array_list_length(options->query_params);
        if (query_len) {
            /* for the '?' */
            buffer_size += 1;
            for (size_t i = 0; i < query_len; ++i) {
                struct aws_uri_param *uri_param_ptr = NULL;
                aws_array_list_get_at_ptr(options->query_params, (void **)&uri_param_ptr, i);
                /* 2 == 1 for '&' and 1 for '='. who cares if we over-allocate a little?  */
                buffer_size += uri_param_ptr->key.len + uri_param_ptr->value.len + 2;
            }
        }
    } else if (options->query_string.len) {
        /* for the '?' */
        buffer_size += 1;
        buffer_size += options->query_string.len;
    }

    if (aws_byte_buf_init(&uri->uri_str, allocator, buffer_size)) {
        return AWS_OP_ERR;
    }

    uri->uri_str.len = 0;
    if (options->scheme.len) {
        aws_byte_buf_append(&uri->uri_str, &options->scheme);
        struct aws_byte_cursor scheme_app = aws_byte_cursor_from_c_str("://");
        aws_byte_buf_append(&uri->uri_str, &scheme_app);
    }

    aws_byte_buf_append(&uri->uri_str, &options->host_name);

    struct aws_byte_cursor port_app = aws_byte_cursor_from_c_str(":");
    if (options->port) {
        aws_byte_buf_append(&uri->uri_str, &port_app);
        char port_arr[6] = {0};
        sprintf(port_arr, "%" PRIu16, options->port);
        struct aws_byte_cursor port_csr = aws_byte_cursor_from_c_str(port_arr);
        aws_byte_buf_append(&uri->uri_str, &port_csr);
    }

    aws_byte_buf_append(&uri->uri_str, &options->path);

    struct aws_byte_cursor query_app = aws_byte_cursor_from_c_str("?");

    if (options->query_params) {
        struct aws_byte_cursor query_param_app = aws_byte_cursor_from_c_str("&");
        struct aws_byte_cursor key_value_delim = aws_byte_cursor_from_c_str("=");

        aws_byte_buf_append(&uri->uri_str, &query_app);
        size_t query_len = aws_array_list_length(options->query_params);
        for (size_t i = 0; i < query_len; ++i) {
            struct aws_uri_param *uri_param_ptr = NULL;
            aws_array_list_get_at_ptr(options->query_params, (void **)&uri_param_ptr, i);
            aws_byte_buf_append(&uri->uri_str, &uri_param_ptr->key);
            aws_byte_buf_append(&uri->uri_str, &key_value_delim);
            aws_byte_buf_append(&uri->uri_str, &uri_param_ptr->value);

            if (i < query_len - 1) {
                aws_byte_buf_append(&uri->uri_str, &query_param_app);
            }
        }
    } else if (options->query_string.len) {
        aws_byte_buf_append(&uri->uri_str, &query_app);
        aws_byte_buf_append(&uri->uri_str, &options->query_string);
    }

    return s_init_from_uri_str(uri);
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

const struct aws_byte_cursor *aws_uri_authority(const struct aws_uri *uri) {
    return &uri->authority;
}

const struct aws_byte_cursor *aws_uri_path(const struct aws_uri *uri) {
    return &uri->path;
}

const struct aws_byte_cursor *aws_uri_query_string(const struct aws_uri *uri) {
    return &uri->query_string;
}

const struct aws_byte_cursor *aws_uri_path_and_query(const struct aws_uri *uri) {
    return &uri->path_and_query;
}

const struct aws_byte_cursor *aws_uri_host_name(const struct aws_uri *uri) {
    return &uri->host_name;
}

uint16_t aws_uri_port(const struct aws_uri *uri) {
    return uri->port;
}

int aws_uri_query_string_params(const struct aws_uri *uri, struct aws_array_list *out_params) {
    if (uri->query_string.len == 0) {
        return AWS_OP_SUCCESS;
    }

    struct aws_array_list key_val_array;
    if (aws_array_list_init_dynamic(&key_val_array, uri->allocator, 8, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    if (aws_byte_cursor_split_on_char(&uri->query_string, '&', &key_val_array)) {
        goto error;
    }

    for (size_t i = 0; i < aws_array_list_length(&key_val_array); ++i) {
        struct aws_byte_cursor *key_val = NULL;
        aws_array_list_get_at_ptr(&key_val_array, (void *)&key_val, i);

        uint8_t *delim = memchr(key_val->ptr, '=', key_val->len);

        if (delim) {
            struct aws_uri_param param_value = {
                .key =
                    {
                        .ptr = key_val->ptr,
                        .len = delim - key_val->ptr,
                    },
                .value =
                    {
                        .ptr = delim + 1,
                        .len = key_val->len - (delim - key_val->ptr) - 1,
                    },
            };

            if (aws_array_list_push_back(out_params, &param_value)) {
                goto error;
            }
        } else {
            struct aws_uri_param param_value = {
                .key =
                    {
                        .ptr = key_val->ptr,
                        .len = key_val->len,
                    },
            };
            AWS_ZERO_STRUCT(param_value.value);

            if (aws_array_list_push_back(out_params, &param_value)) {
                goto error;
            }
        }
    }

    aws_array_list_clean_up(&key_val_array);
    return AWS_OP_SUCCESS;
error:
    aws_array_list_clean_up(&key_val_array);
    aws_array_list_clear(out_params);
    return AWS_OP_ERR;
}

static void s_parse_scheme(struct uri_parser *parser, struct aws_byte_cursor *str) {
    uint8_t *location_of_colon = memchr(str->ptr, ':', str->len);

    if (!location_of_colon) {
        parser->state = ON_AUTHORITY;
        return;
    }

    /* make sure we didn't just pick up the port by mistake */
    if ((size_t)(location_of_colon - str->ptr) < str->len && *(location_of_colon + 1) != '/') {
        parser->state = ON_AUTHORITY;
        return;
    }

    const size_t scheme_len = location_of_colon - str->ptr;
    parser->uri->scheme = aws_byte_cursor_advance(str, scheme_len);

    if (str->len < 3 || str->ptr[0] != ':' || str->ptr[1] != '/' || str->ptr[2] != '/') {
        aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
        parser->state = ERROR;
        return;
    }

    /* advance past the "://" */
    aws_byte_cursor_advance(str, 3);
    parser->state = ON_AUTHORITY;
}

static const char *s_default_path = "/";

static void s_parse_authority(struct uri_parser *parser, struct aws_byte_cursor *str) {
    uint8_t *location_of_slash = memchr(str->ptr, '/', str->len);
    uint8_t *location_of_qmark = memchr(str->ptr, '?', str->len);

    if (!location_of_slash && !location_of_qmark && str->len) {
        parser->uri->authority.ptr = str->ptr;
        parser->uri->authority.len = str->len;

        parser->uri->path.ptr = (uint8_t *)s_default_path;
        parser->uri->path.len = 1;
        parser->uri->path_and_query = parser->uri->path;
        parser->state = FINISHED;
        aws_byte_cursor_advance(str, parser->uri->authority.len);
    } else if (!str->len) {
        parser->state = ERROR;
        aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
        return;
    } else {
        uint8_t *end = str->ptr + str->len;
        if (location_of_slash) {
            parser->state = ON_PATH;
            end = location_of_slash;
        } else if (location_of_qmark) {
            parser->state = ON_QUERY_STRING;
            end = location_of_qmark;
        }

        parser->uri->authority = aws_byte_cursor_advance(str, end - str->ptr);
    }

    struct aws_byte_cursor authority_parse_csr = parser->uri->authority;

    if (authority_parse_csr.len) {
        uint8_t *port_delim = memchr(authority_parse_csr.ptr, ':', authority_parse_csr.len);

        if (!port_delim) {
            parser->uri->port = 0;
            parser->uri->host_name = parser->uri->authority;
            return;
        }

        parser->uri->host_name.ptr = authority_parse_csr.ptr;
        parser->uri->host_name.len = port_delim - authority_parse_csr.ptr;

        size_t port_len = parser->uri->authority.len - parser->uri->host_name.len - 1;
        port_delim += 1;
        for (size_t i = 0; i < port_len; ++i) {
            if (!aws_isdigit(port_delim[i])) {
                parser->state = ERROR;
                aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
                return;
            }
        }

        if (port_len > 5) {
            parser->state = ERROR;
            aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
            return;
        }

        /* why 6? because the port is a 16-bit unsigned integer*/
        char atoi_buf[6] = {0};
        memcpy(atoi_buf, port_delim, port_len);
        int port_int = atoi(atoi_buf);
        if (port_int > UINT16_MAX) {
            parser->state = ERROR;
            aws_raise_error(AWS_ERROR_MALFORMED_INPUT_STRING);
            return;
        }

        parser->uri->port = (uint16_t)port_int;
    }
}

static void s_parse_path(struct uri_parser *parser, struct aws_byte_cursor *str) {
    parser->uri->path_and_query = *str;

    uint8_t *location_of_q_mark = memchr(str->ptr, '?', str->len);

    if (!location_of_q_mark) {
        parser->uri->path.ptr = str->ptr;
        parser->uri->path.len = str->len;
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
    parser->uri->path.len = location_of_q_mark - str->ptr;
    aws_byte_cursor_advance(str, parser->uri->path.len);
    parser->state = ON_QUERY_STRING;
}

static void s_parse_query_string(struct uri_parser *parser, struct aws_byte_cursor *str) {
    if (!parser->uri->path_and_query.ptr) {
        parser->uri->path_and_query = *str;
    }
    /* we don't want the '?' character. */
    if (str->len) {
        parser->uri->query_string.ptr = str->ptr + 1;
        parser->uri->query_string.len = str->len - 1;
    }

    aws_byte_cursor_advance(str, parser->uri->query_string.len + 1);
    parser->state = FINISHED;
}

static uint8_t s_to_uppercase_hex(uint8_t value) {
    AWS_ASSERT(value < 16);

    if (value < 10) {
        return (uint8_t)('0' + value);
    }

    return (uint8_t)('A' + value - 10);
}

typedef void(unchecked_append_canonicalized_character_fn)(struct aws_byte_buf *buffer, uint8_t value);

/*
 * Appends a character or its hex encoding to the buffer.  We reserve enough space up front so that
 * we can do this with raw pointers rather than multiple function calls/cursors/etc...
 *
 * This function is for the uri path
 */
static void s_unchecked_append_canonicalized_path_character(struct aws_byte_buf *buffer, uint8_t value) {
    AWS_ASSERT(buffer->len + 3 <= buffer->capacity);

    uint8_t *dest_ptr = buffer->buffer + buffer->len;

    if (aws_isalnum(value)) {
        ++buffer->len;
        *dest_ptr = value;
        return;
    }

    switch (value) {
        case '-':
        case '_':
        case '.':
        case '~':
        case '$':
        case '&':
        case ',':
        case '/':
        case ':':
        case ';':
        case '=':
        case '@': {
            ++buffer->len;
            *dest_ptr = value;
            return;
        }

        default:
            buffer->len += 3;
            *dest_ptr++ = '%';
            *dest_ptr++ = s_to_uppercase_hex(value >> 4);
            *dest_ptr = s_to_uppercase_hex(value & 0x0F);
            return;
    }
}

/*
 * Appends a character or its hex encoding to the buffer.  We reserve enough space up front so that
 * we can do this with raw pointers rather than multiple function calls/cursors/etc...
 *
 * This function is for query params
 */
static void s_raw_append_canonicalized_param_character(struct aws_byte_buf *buffer, uint8_t value) {
    AWS_ASSERT(buffer->len + 3 <= buffer->capacity);

    uint8_t *dest_ptr = buffer->buffer + buffer->len;

    if (aws_isalnum(value)) {
        ++buffer->len;
        *dest_ptr = value;
        return;
    }

    switch (value) {
        case '-':
        case '_':
        case '.':
        case '~': {
            ++buffer->len;
            *dest_ptr = value;
            return;
        }

        default:
            buffer->len += 3;
            *dest_ptr++ = '%';
            *dest_ptr++ = s_to_uppercase_hex(value >> 4);
            *dest_ptr = s_to_uppercase_hex(value & 0x0F);
            return;
    }
}

/*
 * Writes a cursor to a buffer using the supplied encoding function.
 */
static int s_encode_cursor_to_buffer(
    struct aws_byte_buf *buffer,
    const struct aws_byte_cursor *cursor,
    unchecked_append_canonicalized_character_fn *append_canonicalized_character) {
    uint8_t *current_ptr = cursor->ptr;
    uint8_t *end_ptr = cursor->ptr + cursor->len;

    /*
     * reserve room up front for the worst possible case: everything gets % encoded
     */
    size_t capacity_needed = 0;
    if (AWS_UNLIKELY(aws_mul_size_checked(3, cursor->len, &capacity_needed))) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_reserve_relative(buffer, capacity_needed)) {
        return AWS_OP_ERR;
    }

    while (current_ptr < end_ptr) {
        append_canonicalized_character(buffer, *current_ptr);
        ++current_ptr;
    }

    return AWS_OP_SUCCESS;
}

int aws_byte_buf_append_encoding_uri_path(struct aws_byte_buf *buffer, const struct aws_byte_cursor *cursor) {
    return s_encode_cursor_to_buffer(buffer, cursor, s_unchecked_append_canonicalized_path_character);
}

int aws_byte_buf_append_encoding_uri_param(struct aws_byte_buf *buffer, const struct aws_byte_cursor *cursor) {
    return s_encode_cursor_to_buffer(buffer, cursor, s_raw_append_canonicalized_param_character);
}

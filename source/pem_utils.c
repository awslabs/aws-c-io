/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/string.h>
#include <aws/io/private/pem_utils.h>

enum aws_pem_util_state {
    APUS_BEGIN,
    APUS_ON_DATA,
    APUS_END,
};

static const struct aws_byte_cursor begin_header = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----BEGIN");
static const struct aws_byte_cursor end_header = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----END");
static const struct aws_byte_cursor dashes = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("-----");

static int s_sanitize_pem(
    struct aws_byte_cursor pem_cursor,
    struct aws_allocator *allocator,
    struct aws_byte_buf *output) {
    if (pem_cursor.len == 0) {
        return AWS_OP_SUCCESS;
    }

    int result = AWS_OP_ERR;
    struct aws_byte_buf clean_pem_buf;
    if (aws_byte_buf_init(&clean_pem_buf, allocator, pem_cursor.len)) {
        return result;
    }

    enum aws_pem_util_state state = APUS_BEGIN;

    for (size_t i = 0; i < pem_cursor.len; i++) {
        /* parse through the pem once */
        char current = *(pem_cursor.ptr + i);
        switch (state) {
            case APUS_BEGIN:
                if (current == '-') {
                    struct aws_byte_cursor compare_cursor = pem_cursor;
                    compare_cursor.len = begin_header.len;
                    compare_cursor.ptr += i;
                    if (aws_byte_cursor_eq(&compare_cursor, &begin_header)) {
                        state = APUS_ON_DATA;
                        i--;
                    }
                }
                break;
            case APUS_ON_DATA:
                /* start copying everything */
                if (current == '-') {
                    struct aws_byte_cursor compare_cursor = pem_cursor;
                    compare_cursor.len = end_header.len;
                    compare_cursor.ptr += i;
                    if (aws_byte_cursor_eq(&compare_cursor, &end_header)) {
                        /* Copy the end header string and start to search for the end part of a pem */
                        state = APUS_END;
                        aws_byte_buf_append(&clean_pem_buf, &end_header);
                        i += (end_header.len - 1);
                        break;
                    }
                }
                aws_byte_buf_append_byte_dynamic(&clean_pem_buf, (uint8_t)current);
                break;
            case APUS_END:
                if (current == '-') {
                    struct aws_byte_cursor compare_cursor = pem_cursor;
                    compare_cursor.len = dashes.len;
                    compare_cursor.ptr += i;
                    if (aws_byte_cursor_eq(&compare_cursor, &dashes)) {
                        /* End part of a pem, copy the last 5 dashes and a new line, then ignore everything before next
                         * begin header */
                        state = APUS_BEGIN;
                        aws_byte_buf_append(&clean_pem_buf, &dashes);
                        i += (dashes.len - 1);
                        aws_byte_buf_append_byte_dynamic(&clean_pem_buf, (uint8_t)'\n');
                        break;
                    }
                }
                aws_byte_buf_append_byte_dynamic(&clean_pem_buf, (uint8_t)current);
                break;
            default:
                break;
        }
    }
    struct aws_byte_cursor clean_pem_cursor = aws_byte_cursor_from_buf(&clean_pem_buf);

    aws_byte_buf_reset(output, true);
    if (aws_byte_buf_append_dynamic(output, &clean_pem_cursor) == AWS_OP_SUCCESS) {
        result = AWS_OP_SUCCESS;
    }

    aws_byte_buf_clean_up(&clean_pem_buf);

    return result;
}

int aws_sanitize_pem(struct aws_byte_buf *pem, struct aws_allocator *allocator) {
    return s_sanitize_pem(aws_byte_cursor_from_buf(pem), allocator, pem);
}

struct aws_string *aws_sanitize_pem_to_string(struct aws_byte_cursor pem_cursor, struct aws_allocator *allocator) {
    struct aws_byte_buf pem_buf;
    if (aws_byte_buf_init(&pem_buf, allocator, pem_cursor.len + 1)) {
        return NULL;
    }

    struct aws_string *pem_string = NULL;
    if (s_sanitize_pem(pem_cursor, allocator, &pem_buf)) {
        goto done;
    }

    pem_string = aws_string_new_from_buf(allocator, &pem_buf);

done:

    aws_byte_buf_clean_up(&pem_buf);

    return pem_string;
}

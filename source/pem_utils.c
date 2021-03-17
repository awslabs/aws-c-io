/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/string.h>
#include <aws/io/private/pem_utils.h>

enum aws_pem_util_state {
    BEGIN,
    ON_DATA,
    END,
};

int aws_clean_up_pem(struct aws_byte_buf *pem, struct aws_allocator *allocator) {
    char *clean_pem = NULL;
    clean_pem = aws_mem_calloc(allocator, pem->len, sizeof(char));
    if (!clean_pem) {
        return AWS_OP_ERR;
    }
    struct aws_byte_cursor pem_cursor = aws_byte_cursor_from_buf(pem);
    int state = BEGIN;
    int clean_pem_index = 0;
    const char *begin_header = "-----BEGIN";
    const char *end_header = "-----END";
    const char *dashes = "-----";
    size_t begin_header_len = strlen(begin_header);
    size_t end_header_len = strlen(end_header);
    size_t dashes_len = strlen(dashes);

    for (size_t i = 0; i < pem_cursor.len; i++) {
        /* parse through the pem once */
        char current = *(pem_cursor.ptr + i);
        switch (state) {
            case BEGIN:
                if (current == '-') {
                    if (!strncmp((const char *)(pem_cursor.ptr + i), begin_header, begin_header_len)) {
                        state = ON_DATA;
                        i--;
                    }
                }
                break;
            case ON_DATA:
                /* start copying everything */
                clean_pem[clean_pem_index++] = current;
                if (current == '-') {
                    if (!strncmp((const char *)(pem_cursor.ptr + i), end_header, end_header_len)) {
                        /* Copy the end header string and start to search for the end part of a pem */
                        clean_pem_index--;
                        state = END;
                        for (size_t index = 0; index < end_header_len; index++) {
                            clean_pem[clean_pem_index++] = end_header[index];
                        }
                        i += (end_header_len - 1);
                    }
                }
                break;
            case END:
                clean_pem[clean_pem_index++] = current;
                if (current == '-') {
                    if (!strncmp((const char *)(pem_cursor.ptr + i), dashes, dashes_len)) {
                        /* End part of a pem, copy the last 5 dashes and a new line, then ignore everything before next
                         * begin header */
                        clean_pem_index--;
                        state = BEGIN;
                        for (size_t index = 0; index < dashes_len; index++) {
                            clean_pem[clean_pem_index++] = dashes[index];
                        }
                        i += (dashes_len - 1);
                        clean_pem[clean_pem_index++] = '\n';
                    }
                }
            default:
                break;
        }
    }
    struct aws_byte_cursor clean_pem_cursor = aws_byte_cursor_from_array(clean_pem, clean_pem_index);
    aws_byte_buf_reset(pem, true);
    aws_byte_buf_append(pem, &clean_pem_cursor);
    aws_mem_release(allocator, clean_pem);
    return AWS_OP_SUCCESS;
}

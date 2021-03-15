/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/string.h>
#include <aws/io/private/pem_utils.h>

enum aws_pem_util_state {
    BEFORE_DASH_PART,
    ITERATE_DASH_PART,
    BETWEEN_DASH_PART,
    CONTENT_PART,
};

static const int NUM_DASH_PARTS_PEM = 4;
static const int ALLOWED_CHARS_PER_LINE = 64;

/**
 * RFC7468
 * https://tools.ietf.org/html/rfc7468#section-3
 */
static const bool s_base64_encoding_table[256] = {
    ['0'] = true, ['1'] = true, ['2'] = true, ['3'] = true, ['4'] = true, ['5'] = true, ['6'] = true,
    ['7'] = true, ['8'] = true, ['9'] = true,

    ['A'] = true, ['B'] = true, ['C'] = true, ['D'] = true, ['E'] = true, ['F'] = true, ['G'] = true,
    ['H'] = true, ['I'] = true, ['J'] = true, ['K'] = true, ['L'] = true, ['M'] = true, ['N'] = true,
    ['O'] = true, ['P'] = true, ['Q'] = true, ['R'] = true, ['S'] = true, ['T'] = true, ['U'] = true,
    ['V'] = true, ['W'] = true, ['X'] = true, ['Y'] = true, ['Z'] = true,

    ['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true, ['f'] = true, ['g'] = true,
    ['h'] = true, ['i'] = true, ['j'] = true, ['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true,
    ['o'] = true, ['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = true, ['u'] = true,
    ['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true, ['z'] = true,

    ['+'] = true, ['/'] = true, ['='] = true,
};

static const bool s_base64_allowed_white_space_table[256] = {
    ['\r'] = true,
    ['\n'] = true,
    [' '] = true,
};

struct aws_string *aws_clean_up_pem(struct aws_byte_cursor pem, struct aws_allocator *allocator) {
    char *clean_pem = NULL;
    clean_pem = aws_mem_calloc(allocator, pem.len, sizeof(char));
    int state = BEFORE_DASH_PART;
    int clean_pem_index = 0;
    size_t content_len = 0;
    size_t dash_part_counts = 0;

    for (size_t i = 0; i < pem.len - 1; i++) {
        /* parse through the pem once */
        char current = *(pem.ptr + i);
        char next = *(pem.ptr + i + 1);
        if (current == ' ') {
            /* merge space */
            while (i < pem.len - 1) {
                if (next == ' ') {
                    i++;
                    next = *(pem.ptr + i + 1);
                } else {
                    break;
                }
            }
        }
        switch (state) {
            case BEFORE_DASH_PART:
                if (current == '-') {
                    /* start of a dash block. append 5 dashes */
                    for (int iter = 0; iter < 5; iter++) {
                        clean_pem[clean_pem_index++] = '-';
                    }
                    dash_part_counts++;
                    state = ITERATE_DASH_PART;
                    /* fall through */
                } else {
                    break;
                }
            case ITERATE_DASH_PART:
                /* iterating until a encoded character or endline is the next character */
                if (s_base64_encoding_table[(uint8_t)next] || s_base64_allowed_white_space_table[(uint8_t)next]) {
                    if (next == ' ') {
                        /* Remove any spaces next to dashes (Eg "----- BEGIN" will become "-----BEGIN") */
                        break;
                    }
                    if (dash_part_counts % NUM_DASH_PARTS_PEM == 1 || dash_part_counts % NUM_DASH_PARTS_PEM == 3) {
                        state = BETWEEN_DASH_PART;
                    } else if (dash_part_counts % NUM_DASH_PARTS_PEM == 0) {
                        /* the current dash part is the end of one PEM */
                        clean_pem[clean_pem_index++] = '\n';
                        state = BEFORE_DASH_PART;
                    } else {
                        clean_pem[clean_pem_index++] = '\n';
                        state = CONTENT_PART;
                    }
                }
                break;
            case BETWEEN_DASH_PART:
                if (s_base64_encoding_table[(uint8_t)current] || current == ' ') {
                    clean_pem[clean_pem_index++] = current;
                }
                if (next == '-') {
                    state = BEFORE_DASH_PART;
                }
                break;
            case CONTENT_PART: {
                /**
                 * - Only whitespace is a single newline every 64 chars
                 * - All lines exactly 64 Characters long except for the last line.
                 */
                if (s_base64_encoding_table[(uint8_t)current]) {
                    clean_pem[clean_pem_index++] = current;
                    content_len++;
                    if (content_len % ALLOWED_CHARS_PER_LINE == 0) {
                        clean_pem[clean_pem_index++] = '\n';
                    }
                }
                if (next == '-') {
                    if (clean_pem[clean_pem_index] != '\n') {
                        clean_pem[clean_pem_index++] = '\n';
                    }
                    content_len = 0;
                    state = BEFORE_DASH_PART;
                }
                break;
            }
            default:
                break;
        }
    }
    struct aws_string *return_string = aws_string_new_from_array(allocator, (uint8_t *)clean_pem, clean_pem_index);
    aws_mem_release(allocator, clean_pem);
    return return_string;
}

/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/io/pki_utils.h>

#include <aws/common/encoding.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int aws_read_file_to_buffer(struct aws_allocator *alloc, const char *filename,
                            struct aws_byte_buf *out_buf) {
/* yeah yeah, I know and I don't care. */
#ifdef _MSC_VER
#    define _CRT_SECURE_NO_WARNINGS
#endif

    FILE *fp = fopen(filename, "r");

    if (fp) {
        if (fseek(fp, 0L, SEEK_END)) {
            fclose(fp);
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }

        /* yes I know this breaks the coding conventions rule on init and free being at the same scope,
         * but in this case that doesn't make sense since the user would have to know the length of the file.
         * We'll tell the user that we allocate here and if we succeed they free. */
        if (aws_byte_buf_init(alloc, out_buf, (size_t) ftell(fp))) {
            fclose(fp);
            return AWS_OP_ERR;
        }

        if (fseek(fp, 0L, SEEK_SET)) {
            aws_byte_buf_clean_up(out_buf);
            fclose(fp);
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }

        size_t read = fread(out_buf->buffer, 1, out_buf->capacity, fp);
        fclose(fp);
        if (read < out_buf->capacity) {
            aws_secure_zero(out_buf->buffer, out_buf->len);
            aws_byte_buf_clean_up(out_buf);
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }
        out_buf->len = read;

        return 0;
    }

    return aws_raise_error(AWS_IO_FILE_NOT_FOUND);
}

enum PEM_PARSE_STATE {
    BEGIN,
    ON_DATA,
};

void aws_cert_chain_clean_up(struct aws_array_list *cert_chain) {
    for (size_t i = 0; i < aws_array_list_length(cert_chain); ++i) {
        struct aws_byte_buf *decoded_buffer_ptr = NULL;
        aws_array_list_get_at_ptr(cert_chain, (void **)&decoded_buffer_ptr, i);

        if (decoded_buffer_ptr) {
            aws_secure_zero(decoded_buffer_ptr->buffer, decoded_buffer_ptr->len);
            aws_byte_buf_clean_up(decoded_buffer_ptr);
        }
    }

    /* remember, we don't own it so we don't free it, just undo whatever mutations we've done at this point. */
    aws_array_list_clear(cert_chain);
}

static int s_convert_pem_to_raw_base64(struct aws_allocator *allocator, const struct aws_byte_buf *pem,
                                       struct aws_array_list *cert_chain_or_key) {
    enum PEM_PARSE_STATE state = BEGIN;

    struct aws_byte_buf current_cert;
    struct aws_byte_cursor current_cert_cursor;
    const char *begin_header = "-----BEGIN";
    const char *end_header = "-----END";
    size_t begin_header_len = strlen(begin_header);
    size_t end_header_len = strlen(end_header);
    bool on_length_calc = true;

    struct aws_array_list split_buffers;
    if (aws_array_list_init_dynamic(&split_buffers, allocator, 16, sizeof(struct aws_byte_cursor))) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_split_on_char((struct aws_byte_buf *)pem, '\n', &split_buffers)) {
        aws_array_list_clean_up(&split_buffers);
        return AWS_OP_ERR;
    }

    size_t split_count = aws_array_list_length(&split_buffers);
    size_t i = 0;
    size_t index_of_current_cert_start = 0;
    size_t current_cert_len = 0;

    while (i < split_count) {
        struct aws_byte_cursor *current_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&split_buffers, (void **)&current_buf_ptr, i);

        /* burn off the padding in the buffer first. We'll only have to do this once per cert. */
        while (current_buf_ptr->len
               && isspace(*current_buf_ptr->ptr)) aws_byte_cursor_advance(current_buf_ptr, 1);

        switch (state) {
        case BEGIN:
            if (current_buf_ptr->len  > begin_header_len &&
                !strncmp((const char *) current_buf_ptr->ptr, begin_header, begin_header_len)) {
                state = ON_DATA;
                index_of_current_cert_start = i + 1;
            }
            ++i;
            break;
        case ON_DATA:
            if (current_buf_ptr->len > end_header_len &&
                !strncmp((const char *) current_buf_ptr->ptr, end_header, end_header_len)) {
                if (on_length_calc) {
                    on_length_calc = false;
                    state = ON_DATA;
                    i = index_of_current_cert_start;

                    if (aws_byte_buf_init(allocator, &current_cert, current_cert_len)) {
                        goto end_of_loop;
                    }

                    current_cert.len = current_cert.capacity;
                    current_cert_cursor = aws_byte_cursor_from_buf(&current_cert);
                } else {
                    if (aws_array_list_push_back(cert_chain_or_key, &current_cert)) {
                        aws_secure_zero(&current_cert.buffer, current_cert.len);
                        aws_byte_buf_clean_up(&current_cert);
                        goto end_of_loop;
                    }
                    state = BEGIN;
                    on_length_calc = true;
                    current_cert_len = 0;
                    ++i;
                }
            } else {
                if (!on_length_calc) {
                    aws_byte_cursor_write(&current_cert_cursor, current_buf_ptr->ptr, current_buf_ptr->len);
                } else {
                    current_cert_len += current_buf_ptr->len;
                }
                ++i;
            }
            break;
        }
    }

end_of_loop:
    aws_array_list_clean_up(&split_buffers);

    if (state == BEGIN  && aws_array_list_length(cert_chain_or_key) > 0) {
        return AWS_OP_SUCCESS;
    }

    aws_cert_chain_clean_up(cert_chain_or_key);
    return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
}

int aws_decode_pem_to_buffer_list(struct aws_allocator *alloc,
                                  const struct aws_byte_buf *pem_buffer,
                                  struct aws_array_list *cert_chain_or_key) {
    assert(aws_array_list_length(cert_chain_or_key) == 0);
    struct aws_array_list base_64_buffer_list;

    if (aws_array_list_init_dynamic(&base_64_buffer_list, alloc, 2, sizeof(struct aws_byte_buf))) {
        return AWS_OP_ERR;
    }

    int err_code = AWS_OP_ERR;

    if (s_convert_pem_to_raw_base64(alloc, pem_buffer, &base_64_buffer_list)) {
        goto cleanup_base64_buffer_list;
    }

    for (size_t i = 0; i < aws_array_list_length(&base_64_buffer_list); ++i) {
        size_t decoded_len = 0;
        struct aws_byte_buf *byte_buf_ptr = NULL;
        aws_array_list_get_at_ptr(&base_64_buffer_list, (void **)&byte_buf_ptr, i);

        if (aws_base64_compute_decoded_len((const char *)byte_buf_ptr->buffer, byte_buf_ptr->len, &decoded_len)) {
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto cleanup_output_due_to_error;
        }

        struct aws_byte_buf decoded_buffer;

        if (aws_byte_buf_init(alloc, &decoded_buffer, decoded_len)) {
            goto cleanup_output_due_to_error;
        }

        if (aws_base64_decode(byte_buf_ptr, &decoded_buffer)) {
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            aws_byte_buf_clean_up(&decoded_buffer);
            goto cleanup_output_due_to_error;
        }

        if (aws_array_list_push_back(cert_chain_or_key, &decoded_buffer)) {
            aws_byte_buf_clean_up(&decoded_buffer);
            goto cleanup_output_due_to_error;
        }
    }

    err_code = AWS_OP_SUCCESS;

cleanup_base64_buffer_list:
    aws_cert_chain_clean_up(&base_64_buffer_list);
    aws_array_list_clean_up(&base_64_buffer_list);

    return err_code;


cleanup_output_due_to_error:
    aws_cert_chain_clean_up(&base_64_buffer_list);
    aws_array_list_clean_up(&base_64_buffer_list);

    aws_cert_chain_clean_up(cert_chain_or_key);

    return AWS_OP_ERR;
}

int aws_read_and_decode_pem_file_to_buffer_list(struct aws_allocator *alloc, const char *filename,
                                           struct aws_array_list *cert_chain_or_key) {
    struct aws_byte_buf raw_file_buffer;
    AWS_ZERO_STRUCT(raw_file_buffer);

    if (aws_read_file_to_buffer(alloc, filename, &raw_file_buffer)) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer_list(alloc, &raw_file_buffer, cert_chain_or_key)) {
        aws_secure_zero(raw_file_buffer.buffer, raw_file_buffer.len);
        aws_byte_buf_clean_up(&raw_file_buffer);
        return AWS_OP_ERR;
    }

    aws_secure_zero(raw_file_buffer.buffer, raw_file_buffer.len);
    aws_byte_buf_clean_up(&raw_file_buffer);

    return AWS_OP_SUCCESS;
}

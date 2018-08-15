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
#include <aws/io/file_utils.h>

#include <aws/common/encoding.h>
#include <stdio.h>

int aws_read_file_to_buffer(struct aws_allocator *alloc, const char *filename,
                            struct aws_byte_buf *out_buf) {
    FILE *fp = fopen(filename, "r");

    if (fp) {
        fseek(fp, 0L, SEEK_END);
        /* yes I know this breaks the coding conventions rule on init and free being at the same scope,
         * but in this case that doesn't make sense since the user would have to know the length of the file.
         * We'll tell the user that we allocate here and if we succeed they free. */
        if (aws_byte_buf_init(alloc, out_buf, (size_t) ftell(fp))) {
            fclose(fp);
            return AWS_OP_ERR;
        }

        fseek(fp, 0L, SEEK_SET);

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

enum PEM_TO_DER_STATE {
    BEGIN,
    ON_DATA,
    ON_END_OF_CERT,
    END_OF_CERT_OR_FINISHED
};

void aws_cert_chain_clean_up(struct aws_array_list *buffer_list) {
    for (size_t i = 0; i < aws_array_list_length(buffer_list); ++i) {
        struct aws_byte_buf *decoded_buffer_ptr = NULL;
        aws_array_list_get_at_ptr(buffer_list, (void **)&decoded_buffer_ptr, i);

        if (decoded_buffer_ptr) {
            aws_secure_zero(decoded_buffer_ptr->buffer, decoded_buffer_ptr->len);
            aws_byte_buf_clean_up(decoded_buffer_ptr);
        }

        /* remember, we don't own it so we don't free it, just undo whatever mutations we've done at this point. */
        aws_array_list_clear(buffer_list);
    }
}

static int s_convert_pem_to_raw_base64(struct aws_allocator *allocator, const struct aws_byte_buf *pem,
                                       struct aws_array_list *cert_chain_or_key) {
    enum PEM_TO_DER_STATE state = BEGIN;
    struct aws_byte_cursor pem_cursor = aws_byte_cursor_from_buf(pem);

    size_t begin_offset = 0, end_offset = 0, current_location = 0, written = 0;
    struct aws_byte_buf current_cert;
    aws_byte_buf_init(allocator,  &current_cert, pem->len);
    struct aws_byte_cursor current_cert_cursor;

    while (pem_cursor.ptr && state < ON_END_OF_CERT) {
        switch (state) {
        case BEGIN:
            if (*pem_cursor.ptr == '\n') {
                if (aws_byte_buf_init(allocator,  &current_cert, pem->len - current_location)) {
                    goto end_of_loop;
                }

                current_cert.len = current_cert.capacity;
                current_cert_cursor = aws_byte_cursor_from_buf(&current_cert);
                written = 0;
                begin_offset = current_location + 1;
                state = ON_DATA;
                break;
            }
            break;
        case ON_DATA:
            if (*pem_cursor.ptr == '\n') {
                end_offset = current_location;
                aws_byte_cursor_write(&current_cert_cursor, pem->buffer + begin_offset, end_offset - begin_offset);
                written += end_offset - begin_offset;
                begin_offset = current_location + 1;
                break;
            }

            if (*pem_cursor.ptr == '-') {
                current_cert.len = written;
                if (aws_array_list_push_back(cert_chain_or_key, &current_cert)) {
                    aws_byte_buf_clean_up(&current_cert);
                    goto end_of_loop;
                }

                state = ON_END_OF_CERT;
                break;
            }
            break;
         /* keep in mind, an entire chain of certs can be in a single PEM file. */
        case ON_END_OF_CERT:
            if (*pem_cursor.ptr == '\n') {
                state = END_OF_CERT_OR_FINISHED;
                break;
            }
            break;
        case END_OF_CERT_OR_FINISHED:
            if (*pem_cursor.ptr == '-') {
                state = BEGIN;
                break;
            }
            break;
        }
        aws_byte_cursor_advance(&pem_cursor, 1);
        current_location++;
    }

end_of_loop:
    if (state >= ON_END_OF_CERT) {
        return AWS_OP_SUCCESS;
    }
    else {
        aws_cert_chain_clean_up(cert_chain_or_key);
        return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
    }

}

int aws_decode_pem_to_buffer_list(struct aws_allocator *alloc,
                                  const struct aws_byte_buf *pem_buffer,
                                  struct aws_array_list *cert_chain_or_key) {
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
            goto cleanup_output_due_to_error;
        }

        struct aws_byte_buf decoded_buffer;
        AWS_ZERO_STRUCT(decoded_buffer);
        if (aws_byte_buf_init(alloc, &decoded_buffer, decoded_len)) {
            goto cleanup_output_due_to_error;
        }

        if (aws_base64_decode(byte_buf_ptr, &decoded_buffer)) {
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

    for (size_t i = 0; i < aws_array_list_length(cert_chain_or_key); ++i) {
        struct aws_byte_buf *decoded_buffer_ptr = NULL;
        aws_array_list_get_at_ptr(cert_chain_or_key, (void **)&decoded_buffer_ptr, i);

        if (decoded_buffer_ptr) {
            aws_secure_zero(decoded_buffer_ptr->buffer, decoded_buffer_ptr->len);
            aws_byte_buf_clean_up(decoded_buffer_ptr);
        }

        /* remember, we don't own it so we don't free it, just undo whatever mutations we've done at this point. */
        aws_array_list_clear(cert_chain_or_key);
    }

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

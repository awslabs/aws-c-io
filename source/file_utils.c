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
    FINISHED

};

static int convert_pem_to_raw_base64(const struct aws_byte_buf *pem, struct aws_byte_buf *output) {
    enum PEM_TO_DER_STATE state = BEGIN;
    struct aws_byte_cursor pem_cursor = aws_byte_cursor_from_buf(pem);

    if (aws_byte_buf_init(pem->allocator, output, pem->len)) {
        return AWS_OP_ERR;
    }
    output->len = pem->len;

    struct aws_byte_cursor output_cursor = aws_byte_cursor_from_buf(output);

    while (pem_cursor.ptr && state < FINISHED) {
        switch (state) {
        case BEGIN:
            if (*pem_cursor.ptr == '\n') {
                state = ON_DATA;
                break;
            }
            break;
        case ON_DATA:
            if (*pem_cursor.ptr == '\n') {
                break;
            }
            if (*pem_cursor.ptr == '-') {
                state = FINISHED;
                break;
            }
            aws_byte_cursor_write(&output_cursor, pem_cursor.ptr, 1);
            break;
        case FINISHED:
            break;
        }
        aws_byte_cursor_advance(&pem_cursor, 1);
    }
    output->len = output_cursor.ptr - output->buffer;

    if (state == FINISHED) {
        return AWS_OP_SUCCESS;
    }
    else {
        return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
    }

}

int aws_decode_pem_to_buffer(struct aws_allocator *alloc,
                             const struct aws_byte_buf *pem_buffer, struct aws_byte_buf *out_buf) {
    struct aws_byte_buf base_64_buffer;

    if (convert_pem_to_raw_base64(pem_buffer, &base_64_buffer)) {
        return AWS_OP_ERR;
    }

    size_t decoded_len = 0;
    aws_base64_compute_decoded_len((const char *)base_64_buffer.buffer, base_64_buffer.len, &decoded_len);

    aws_byte_buf_init(alloc, out_buf, decoded_len);
    aws_base64_decode(&base_64_buffer, out_buf);

    aws_secure_zero(base_64_buffer.buffer, base_64_buffer.len);
    aws_byte_buf_clean_up(&base_64_buffer);
    return AWS_OP_SUCCESS;
}

int aws_read_and_decode_pem_file_to_buffer(struct aws_allocator *alloc, const char *filename,
                                           struct aws_byte_buf *out_buf) {
    struct aws_byte_buf raw_file_buffer;
    AWS_ZERO_STRUCT(raw_file_buffer);

    if (aws_read_file_to_buffer(alloc, filename, &raw_file_buffer)) {
        return AWS_OP_ERR;
    }

    if (aws_decode_pem_to_buffer(alloc, &raw_file_buffer, out_buf)) {
        aws_secure_zero(raw_file_buffer.buffer, raw_file_buffer.len);
        aws_byte_buf_clean_up(&raw_file_buffer);
        return AWS_OP_ERR;
    }

    aws_secure_zero(raw_file_buffer.buffer, raw_file_buffer.len);
    aws_byte_buf_clean_up(&raw_file_buffer);

    return AWS_OP_SUCCESS;
}

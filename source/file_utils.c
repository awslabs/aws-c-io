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

#include <aws/io/file_utils.h>

#include <errno.h>
#include <stdio.h>

int aws_byte_buf_init_from_file(struct aws_byte_buf *out_buf, struct aws_allocator *alloc, const char *filename) {
#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about fopen() being insecure */
#endif                              /* _MSC_VER */

    AWS_ZERO_STRUCT(*out_buf);
    FILE *fp = fopen(filename, "rb");

    if (fp) {
        if (fseek(fp, 0L, SEEK_END)) {
            fclose(fp);
            return aws_io_translate_and_raise_file_open_error(errno);
        }

        size_t allocation_size = (size_t)ftell(fp) + 1;
        /* Tell the user that we allocate here and if success they're responsible for the free. */
        if (aws_byte_buf_init(out_buf, alloc, allocation_size)) {
            fclose(fp);
            return AWS_OP_ERR;
        }

        /* Ensure compatibility with null-terminated APIs, but don't consider
         * the null terminator part of the length of the payload */
        out_buf->len = out_buf->capacity - 1;
        out_buf->buffer[out_buf->len] = 0;

        if (fseek(fp, 0L, SEEK_SET)) {
            aws_byte_buf_clean_up(out_buf);
            fclose(fp);
            return aws_io_translate_and_raise_file_open_error(errno);
        }

        size_t read = fread(out_buf->buffer, 1, out_buf->len, fp);
        fclose(fp);
        if (read < out_buf->len) {
            aws_secure_zero(out_buf->buffer, out_buf->len);
            aws_byte_buf_clean_up(out_buf);
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }

        return AWS_OP_SUCCESS;
    }

    return aws_io_translate_and_raise_file_open_error(errno);
}

int aws_io_translate_and_raise_file_open_error(int error_no) {
    switch (error_no) {
        case EPERM:
        case EACCES:
            return aws_raise_error(AWS_IO_NO_PERMISSION);
        case EISDIR:
        case ENAMETOOLONG:
        case ENOENT:
            return aws_raise_error(AWS_IO_FILE_INVALID_PATH);
        case ENFILE:
            return aws_raise_error(AWS_IO_MAX_FDS_EXCEEDED);
        case ENOMEM:
            return aws_raise_error(AWS_ERROR_OOM);
        default:
            return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }
}

int aws_io_translate_and_raise_file_write_error(int error_no) {
    switch(error_no) {
        default:
            return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }
}

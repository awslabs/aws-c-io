#ifndef AWS_IO_FILE_UTILS_H
#define AWS_IO_FILE_UTILS_H

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

AWS_EXTERN_C_BEGIN

/**
 * Reads 'filename' into 'out_buf'. If successful, 'out_buf' is allocated and filled with the data;
 * It is your responsibility to call 'aws_byte_buf_clean_up()' on it. Otherwise, 'out_buf' remains
 * unused. In the very unfortunate case where some API needs to treat out_buf as a c_string, a null terminator
 * is appended, but is not included as part of the length field.
 */
AWS_IO_API int aws_byte_buf_init_from_file(
    struct aws_byte_buf *out_buf,
    struct aws_allocator *alloc,
    const char *filename);

/**
 * Convert a c library error from opening a file into an aws error.  Consider merging with below.
 */
AWS_IO_API
int aws_io_translate_and_raise_file_open_error(int error_no);

/**
 * Convert a c library error from reading a file into an aws error. Consider merging with above.
 */
AWS_IO_API
int aws_io_translate_and_raise_file_write_error(int error_no);

/**
 * Returns true iff the character is a directory separator on ANY supported platform.
 */
AWS_IO_API
bool aws_is_directory_separator(char value);

/**
 * Returns the directory separator used by the local platform
 */
AWS_IO_API
char aws_get_local_platform_directory_separator(void);

/**
 * Returns the current user's home directory.
 */
AWS_IO_API
struct aws_string *aws_get_home_directory(struct aws_allocator *allocator);

/**
 * Returns the current user's home directory, if it is stored in the HOME environment variable
 */
AWS_IO_API
struct aws_string *aws_get_home_directory_environment_value(struct aws_allocator *allocator);

AWS_EXTERN_C_END

#endif // AWS_IO_FILE_UTILS_H

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

#include <aws/common/environment.h>
#include <aws/common/string.h>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

char aws_get_platform_directory_separator(void) {
    return '/';
}

AWS_STATIC_STRING_FROM_LITERAL(s_home_env_var, "HOME");

struct aws_string *aws_get_home_directory(struct aws_allocator *allocator) {

    /* ToDo: check getpwuid_r if environment check fails */
    struct aws_string *home_env_var_value = NULL;
    if (aws_get_environment_value(allocator, s_home_env_var, &home_env_var_value) == 0 && home_env_var_value != NULL) {
        return home_env_var_value;
    }

    return NULL;
}

bool aws_path_exists(const char *path) {
    struct stat buffer;
    return stat(path, &buffer) == 0;
}

int aws_fseek(FILE *file, aws_off_t offset, int whence) {

    int result =
#if _FILE_OFFSET_BITS == 64 || _POSIX_C_SOURCE >= 200112L
        fseeko(file, offset, whence);
#else
        fseek(file, offset, whence);
#endif

    if (result != 0) {
        return aws_raise_error(aws_io_translate_and_raise_io_error(errno));
    }

    return AWS_OP_SUCCESS;
}

int aws_file_get_length(FILE *file, size_t *length) {

    struct stat file_stats;

    int fd = fileno(file);
    if (fd == -1) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (fstat(fd, &file_stats)) {
        return aws_raise_error(aws_io_translate_and_raise_io_error(errno));
    }

    *length = file_stats.st_size;

    return AWS_OP_SUCCESS;
}

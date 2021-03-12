/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/file_utils.h>

#include <aws/common/environment.h>
#include <aws/common/string.h>

#include <Shlwapi.h>
#include <io.h>

char aws_get_platform_directory_separator(void) {
    return '\\';
}

AWS_STATIC_STRING_FROM_LITERAL(s_userprofile_env_var, "USERPROFILE");
AWS_STATIC_STRING_FROM_LITERAL(s_homedrive_env_var, "HOMEDRIVE");
AWS_STATIC_STRING_FROM_LITERAL(s_homepath_env_var, "HOMEPATH");

AWS_STATIC_STRING_FROM_LITERAL(s_home_env_var, "HOME");

struct aws_string *aws_get_home_directory(struct aws_allocator *allocator) {

    /*
     * 1. Check HOME
     */
    struct aws_string *home_env_var_value = NULL;
    if (aws_get_environment_value(allocator, s_home_env_var, &home_env_var_value) == 0 && home_env_var_value != NULL) {
        return home_env_var_value;
    }

    /*
     * 2. (Windows) Check USERPROFILE
     */
    struct aws_string *userprofile_env_var_value = NULL;
    if (aws_get_environment_value(allocator, s_userprofile_env_var, &userprofile_env_var_value) == 0 &&
        userprofile_env_var_value != NULL) {
        return userprofile_env_var_value;
    }

    /*
     * 3. (Windows) Check HOMEDRIVE ++ HOMEPATH
     */
    struct aws_string *final_path = NULL;
    struct aws_string *homedrive_env_var_value = NULL;
    if (aws_get_environment_value(allocator, s_homedrive_env_var, &homedrive_env_var_value) == 0 &&
        homedrive_env_var_value != NULL) {
        struct aws_string *homepath_env_var_value = NULL;
        if (aws_get_environment_value(allocator, s_homepath_env_var, &homepath_env_var_value) == 0 &&
            homepath_env_var_value != NULL) {
            struct aws_byte_buf concatenated_dir;
            aws_byte_buf_init(
                &concatenated_dir, allocator, homedrive_env_var_value->len + homepath_env_var_value->len + 1);

            struct aws_byte_cursor drive_cursor = aws_byte_cursor_from_string(homedrive_env_var_value);
            struct aws_byte_cursor path_cursor = aws_byte_cursor_from_string(homepath_env_var_value);

            aws_byte_buf_append(&concatenated_dir, &drive_cursor);
            aws_byte_buf_append(&concatenated_dir, &path_cursor);

            final_path = aws_string_new_from_buf(allocator, &concatenated_dir);

            aws_byte_buf_clean_up(&concatenated_dir);
            aws_string_destroy(homepath_env_var_value);
        }

        aws_string_destroy(homedrive_env_var_value);
    }

    if (final_path != NULL) {
        return final_path;
    }

    return NULL;
}

bool aws_path_exists(const char *path) {
    return PathFileExistsA(path) == TRUE;
}

int aws_fseek(FILE *file, aws_off_t offset, int whence) {
    if (_fseeki64(file, offset, whence)) {
        return aws_translate_and_raise_io_error(errno);
    }

    return AWS_OP_SUCCESS;
}

int aws_file_get_length(FILE *file, int64_t *length) {
    int fd = _fileno(file);
    if (fd == -1) {
        return aws_raise_error(AWS_IO_INVALID_FILE_HANDLE);
    }

    HANDLE os_file = (HANDLE)_get_osfhandle(fd);
    if (os_file == INVALID_HANDLE_VALUE) {
        return aws_translate_and_raise_io_error(errno);
    }

    LARGE_INTEGER os_size;
    if (!GetFileSizeEx(os_file, &os_size)) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    int64_t size = os_size.QuadPart;
    if (size < 0) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    *length = size;

    return AWS_OP_SUCCESS;
}

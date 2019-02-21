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

#include <aws/io/log_writer.h>

#include <aws/common/string.h>
#include <aws/io/file_utils.h>

#include <errno.h>
#include <stdio.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* Disable warnings about fopen() being insecure */
#endif                              /* _MSC_VER */

/*
 * Basic log writer implementations - stdout, stderr, arbitrary file
 */

struct aws_file_writer;

/*
 * All three default implementations use a "subclass" implementation
 * that operates on C library file streams.  Stdout/Stderr implementations
 * do not actually open/close their stream.
 *
 * It is the responsibility of the open vtable function to set the log_file
 * member of the aws_file_writer.
 */
typedef int (*aws_file_writer_open_file_fn)(struct aws_file_writer *writer);
typedef int (*aws_file_writer_close_file_fn)(struct aws_file_writer *writer);

struct aws_file_writer_vtable {
    aws_file_writer_open_file_fn open_file;
    aws_file_writer_close_file_fn close_file;
};

struct aws_file_writer {
    struct aws_file_writer_vtable *vtable;
    FILE *log_file;
    struct aws_string *base_file_name;
};

/*
 * Stdout subclass implementation
 */
static int s_stdout_writer_open_file_fn(struct aws_file_writer *writer) {
    writer->log_file = stdout;

    return AWS_OP_SUCCESS;
}

static int s_stdout_writer_close_file_fn(struct aws_file_writer *writer) {
    (void)writer;

    return AWS_OP_SUCCESS;
}

static struct aws_file_writer_vtable s_stdout_writer_vtable = {.open_file = s_stdout_writer_open_file_fn,
                                                               .close_file = s_stdout_writer_close_file_fn};

/*
 * Stderr subclass implementation
 */
static int s_stderr_writer_open_file_fn(struct aws_file_writer *writer) {
    writer->log_file = stderr;

    return AWS_OP_SUCCESS;
}

static int s_stderr_writer_close_file_fn(struct aws_file_writer *writer) {
    (void)writer;

    return AWS_OP_SUCCESS;
}

static struct aws_file_writer_vtable s_stderr_writer_vtable = {.open_file = s_stderr_writer_open_file_fn,
                                                               .close_file = s_stderr_writer_close_file_fn};

/*
 * File-sink subclass implementation - uses fopen and fclose for now
 */
static int s_file_writer_open_file_fn(struct aws_file_writer *writer) {
    writer->log_file = fopen((const char *)aws_string_bytes(writer->base_file_name), "a+");
    if (writer->log_file == NULL) {
        return aws_io_translate_and_raise_file_open_error(errno);
    }

    return AWS_OP_SUCCESS;
}

static int s_file_writer_close_file_fn(struct aws_file_writer *writer) {
    if (fclose(writer->log_file)) {
        return aws_io_translate_and_raise_file_open_error(errno);
    }

    return AWS_OP_SUCCESS;
}

static struct aws_file_writer_vtable s_file_writer_vtable = {.open_file = s_file_writer_open_file_fn,
                                                             .close_file = s_file_writer_close_file_fn};

/*
 * Shared implementation across all three writers
 */
static int s_aws_file_writer_write_fn(struct aws_log_writer *writer, const struct aws_string *output) {
    struct aws_file_writer *impl = (struct aws_file_writer *)writer->impl;

    size_t length = output->len;
    if (fwrite(output->bytes, 1, length, impl->log_file) < length) {
        return aws_io_translate_and_raise_file_write_error(errno);
    }

    return AWS_OP_SUCCESS;
}

static int s_aws_file_writer_cleanup_fn(struct aws_log_writer *writer) {
    struct aws_file_writer *impl = (struct aws_file_writer *)writer->impl;

    assert(impl->vtable->close_file != NULL);
    int result = (impl->vtable->close_file)(impl);

    if (impl->base_file_name != NULL) {
        aws_mem_release(writer->allocator, impl->base_file_name);
    }

    aws_mem_release(writer->allocator, impl);

    return result;
}

static struct aws_log_writer_vtable s_aws_file_writer_vtable = {.write = s_aws_file_writer_write_fn,
                                                                .cleanup = s_aws_file_writer_cleanup_fn};

/*
 * Shared internal init implementation
 */
static int s_aws_file_writer_init_internal(
    struct aws_log_writer *writer,
    struct aws_allocator *allocator,
    const char *file_name,
    struct aws_file_writer_vtable *vtable) {

    /* Allocate and initialize the file writer */
    struct aws_file_writer *impl = (struct aws_file_writer *)aws_mem_acquire(allocator, sizeof(struct aws_file_writer));
    if (impl == NULL) {
        return AWS_OP_ERR;
    }

    impl->vtable = vtable;
    impl->log_file = NULL;
    impl->base_file_name = NULL;

    /* copy the file name, if necessary */
    if (file_name != NULL) {
        impl->base_file_name = aws_string_new_from_c_str(allocator, file_name);
        if (impl->base_file_name == NULL) {
            aws_mem_release(allocator, impl);
            return AWS_OP_ERR;
        }
    }

    /* attempt to open the file */
    if ((vtable->open_file)(impl)) {
        if (impl->base_file_name != NULL) {
            aws_mem_release(allocator, impl->base_file_name);
        }
        aws_mem_release(allocator, impl);
        return AWS_OP_ERR;
    }

    writer->vtable = &s_aws_file_writer_vtable;
    writer->allocator = allocator;
    writer->impl = impl;

    return AWS_OP_SUCCESS;
}

/*
 * Public initialization interface
 */
int aws_log_writer_stdout_init(struct aws_log_writer *writer, struct aws_allocator *allocator) {
    return s_aws_file_writer_init_internal(writer, allocator, NULL, &s_stdout_writer_vtable);
}

int aws_log_writer_stderr_init(struct aws_log_writer *writer, struct aws_allocator *allocator) {
    return s_aws_file_writer_init_internal(writer, allocator, NULL, &s_stderr_writer_vtable);
}

int aws_log_writer_file_init(
    struct aws_log_writer *writer,
    struct aws_allocator *allocator,
    struct aws_log_writer_file_options *options) {
    return s_aws_file_writer_init_internal(writer, allocator, options->filename, &s_file_writer_vtable);
}

int aws_log_writer_cleanup(struct aws_log_writer *writer) {
    assert(writer->vtable->cleanup);
    return (writer->vtable->cleanup)(writer);
}

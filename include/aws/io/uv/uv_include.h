#ifndef AWS_IO_UV_UV_INCLUDE
#define AWS_IO_UV_UV_INCLUDE

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

/* This file exists to support the UV_HEADER_PATH macro */

/* Default, just search the include paths */
#ifndef UV_HEADER_PATH
#    define UV_HEADER_PATH uv.h
#endif

#define UV_HEADER_PATH_2 <UV_HEADER_PATH>
/* NOLINTNEXTLINE(fuchsia-restrict-system-includes) */
#include UV_HEADER_PATH_2

#endif /* AWS_IO_UV_UV_INCLUDE */

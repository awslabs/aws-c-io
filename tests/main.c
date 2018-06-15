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

#if _MSC_VER
#pragma warning(disable:4100) /* unreferenced formal parameter */
#pragma warning(disable:4204) /* non-constant aggregate initializer */
#pragma warning(disable:4221) /* initialization using address of automatic variable */
#endif

#include <pipe_test.c>
#include <event_loop_test.c>

int main (int argc, char *argv[]) {
#if 0
    AWS_RUN_TEST_CASES(&xthread_scheduled_tasks_execute,
                       &read_write_notifications,
                       &stop_then_restart
                      );
#endif
    AWS_RUN_TEST_CASES(&pipe_open_close,
                       &pipe_read_write,
                       &pipe_read_write_large_buffer,
                      );


}

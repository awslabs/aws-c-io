include(CTest)
enable_testing()

file(GLOB TEST_SRC "main.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

set(TEST_BINARY_NAME ${CMAKE_PROJECT_NAME}-tests)

add_executable(${TEST_BINARY_NAME} ${TESTS})
target_link_libraries(${TEST_BINARY_NAME} ${CMAKE_PROJECT_NAME})
set_target_properties(${TEST_BINARY_NAME} PROPERTIES LINKER_LANGUAGE C C_STANDARD 99)
target_compile_definitions(${TEST_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
if (MSVC)
    target_compile_options(${TEST_BINARY_NAME} PRIVATE /W4 /WX)
else ()
    target_compile_options(${TEST_BINARY_NAME} PRIVATE -Wall -Wno-long-long -Werror)
endif ()

#SSL certificates to use for testing.
add_custom_command(TARGET ${TEST_BINARY_NAME} PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/resources ${CMAKE_CURRENT_BINARY_DIR})

add_test(xthread_scheduled_tasks_execute ${TEST_BINARY_NAME} xthread_scheduled_tasks_execute)
add_test(read_write_notifications ${TEST_BINARY_NAME} read_write_notifications)
add_test(stop_then_restart ${TEST_BINARY_NAME} stop_then_restart)


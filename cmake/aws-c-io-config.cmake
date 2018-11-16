include(CMakeFindDependencyMacro)

if (UNIX AND NOT APPLE)
    find_dependency(s2n)
endif()

find_dependency(aws-c-common)

include(${CMAKE_CURRENT_LIST_DIR}/@CMAKE_PROJECT_NAME@-targets.cmake)

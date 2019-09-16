include(CMakeFindDependencyMacro)

if (UNIX AND NOT APPLE)
    find_dependency(s2n)
endif()

find_dependency(aws-c-common)

if (BUILD_SHARED_LIBS)
    include(${CMAKE_CURRENT_LIST_DIR}/shared/@CMAKE_PROJECT_NAME@-targets.cmake)
else()
    include(${CMAKE_CURRENT_LIST_DIR}/static/@CMAKE_PROJECT_NAME@-targets.cmake)
endif()


include(CMakeFindDependencyMacro)

# USE_S2N is substituted at aws-c-io configure time (configure_file @ONLY) with the
# actual build decision, so this matches whether aws-c-io was really linked against s2n.
if (@USE_S2N@)
    find_dependency(s2n)
endif()

find_dependency(aws-c-common)
find_dependency(aws-c-cal)

macro(aws_load_targets type)
    include(${CMAKE_CURRENT_LIST_DIR}/${type}/@PROJECT_NAME@-targets.cmake)
endmacro()

# try to load the lib follow BUILD_SHARED_LIBS. Fall back if not exist.
if (BUILD_SHARED_LIBS)
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/shared")
        aws_load_targets(shared)
    else()
        aws_load_targets(static)
    endif()
else()
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/static")
        aws_load_targets(static)
    else()
        aws_load_targets(shared)
    endif()
endif()

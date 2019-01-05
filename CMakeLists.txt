
cmake_minimum_required(VERSION 3.1)
project(aws-c-io C)

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake")

include(AwsCFlags)
include(AwsSharedLibSetup)
include(AwsSanitizers)

option(BUILD_RELOCATABLE_BINARIES
        "Build Relocatable Binaries, this will turn off features that will fail on older kernels than used for the build."
        OFF)

file(GLOB AWS_IO_HEADERS
        "include/aws/io/*.h"
        )

file(GLOB AWS_IO_TESTING_HEADERS
        "include/aws/testing/*.h"
        )


file(GLOB AWS_IO_PRIV_HEADERS
        "include/aws/io/private/*.h"
        )

file(GLOB AWS_IO_SRC
        "source/*.c"
        )

if (WIN32)
    option(USE_IO_COMPLETION_PORTS
            "Use I/O Completion Ports to drive event-loops. \
            If disabled, a less performant implementation based on select() is used. \
            Disable this if implementing your own event-loop whose interface does not match the IOCP interface."
            ON)

    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/windows/*.c"
            )

    if (USE_IO_COMPLETION_PORTS)
        file(GLOB AWS_IO_IOCP_SRC
                "source/windows/iocp/*.c"
                )
         list(APPEND AWS_IO_OS_SRC ${AWS_IO_IOCP_SRC})
    endif ()

    if (MSVC)
        source_group("Header Files\\aws\\io" FILES ${AWS_IO_HEADERS})
        source_group("Header Files\\aws\\io\\private" FILES ${AWS_IO_PRIV_HEADERS})
        source_group("Source Files" FILES ${AWS_IO_SRC})
        source_group("Source Files\\windows" FILES ${AWS_IO_OS_SRC})
    endif ()
    #platform libs come from aws-c-common transitively, so we don't specify them here, but for documentation purposes,
    #Kernel32 and wsock2 are pulled in automatically. Here we add the lib containing the schannel API.
    #Also note, you don't get a choice on TLS implementation for Windows.
    set(PLATFORM_LIBS Secur32 Crypt32)
    set(TLS_STACK_DETERMINED ON)

elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/linux/*.c"
            "source/posix/*.c"
            )
    set(PLATFORM_LIBS "")
elseif (APPLE)

    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/bsd/*.c"
            "source/posix/*.c"
            "source/darwin/*.c"
            )

        find_library(SECURITY_LIB Security)
        if (NOT SECURITY_LIB)
            message(FATAL_ERROR "Security framework not found")
        endif ()

        #No choice on TLS for apple, darwinssl will always be used.
        set(PLATFORM_LIBS ${SECURITY_LIB})
        set(TLS_STACK_DETERMINED ON)

elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/bsd/*.c"
            "source/posix/*.c"
            )

endif()

if (NOT CUSTOM_TLS)
    if (USE_S2N)
        set(TLS_STACK_DETERMINED ON)
    endif ()
    if (NOT TLS_STACK_DETERMINED)
        if (NOT WIN32 AND NOT APPLE)
            set(USE_S2N ON)
        endif ()
    endif ()

    if (USE_S2N)
        file(GLOB AWS_IO_TLS_SRC
                "source/s2n/*.c"
                )
        find_package(s2n REQUIRED)
        set(PLATFORM_LIBS ${PlATFORM_LIBS} AWS::s2n)
    endif ()
endif ()

file(GLOB IO_HEADERS
        ${AWS_IO_HEADERS}
        ${AWS_IO_OS_HEADERS}
        ${AWS_IO_PRIV_HEADERS}
        )

file(GLOB IO_SRC
        ${AWS_IO_SRC}
        ${AWS_IO_OS_SRC}
        ${AWS_IO_TLS_SRC}
        )

add_library(${CMAKE_PROJECT_NAME} ${LIBTYPE} ${IO_HEADERS} ${IO_SRC})
aws_set_common_properties(${CMAKE_PROJECT_NAME})
aws_prepare_symbol_visibility_args(${CMAKE_PROJECT_NAME} "AWS_IO")

aws_add_sanitizers(${CMAKE_PROJECT_NAME})

# We are not ABI stable yet
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES VERSION 1.0.0)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES SOVERSION 0unstable)

if (USE_IO_COMPLETION_PORTS)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "-DAWS_USE_IO_COMPLETION_PORTS")
endif ()

if (BUILD_JNI_BINDINGS)
    set(BUILD_RELOCATABLE_BINARIES ON)
    find_package(JNI)
    include_directories(${JNI_INCLUDE_DIRS})
    set(PLATFORM_LIBS ${PLATFORM_LIBS} ${JNI_LIBRARIES})
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE "-DBUILD_JNI_BINDINGS")
endif ()

if (BUILD_RELOCATABLE_BINARIES)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE "-DCOMPAT_MODE")
endif()

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

find_package(aws-c-common REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC AWS::aws-c-common ${PLATFORM_LIBS})

aws_prepare_shared_lib_exports(${CMAKE_PROJECT_NAME})

install(FILES ${AWS_IO_HEADERS} DESTINATION "include/aws/io" COMPONENT Development)
install(FILES ${AWS_IO_TESTING_HEADERS} DESTINATION "include/aws/testing" COMPONENT Development)

install(EXPORT "${CMAKE_PROJECT_NAME}-targets"
        DESTINATION "${LIBRARY_DIRECTORY}/${CMAKE_PROJECT_NAME}/cmake/"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${CMAKE_PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}-config.cmake"
        DESTINATION "${LIBRARY_DIRECTORY}/${CMAKE_PROJECT_NAME}/cmake/"
        COMPONENT Development)

include(CTest)
add_subdirectory(tests)

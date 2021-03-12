
cmake_minimum_required(VERSION 3.1)
project(aws-c-io C)

if (POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW) # Enable LTO/IPO if available in the compiler, see AwsCFlags
endif()

if (DEFINED CMAKE_PREFIX_PATH)
    file(TO_CMAKE_PATH "${CMAKE_PREFIX_PATH}" CMAKE_PREFIX_PATH)
endif()

if (DEFINED CMAKE_INSTALL_PREFIX)
    file(TO_CMAKE_PATH "${CMAKE_INSTALL_PREFIX}" CMAKE_INSTALL_PREFIX)
endif()


if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

# This is required in order to append /lib/cmake to each element in CMAKE_PREFIX_PATH
set(AWS_MODULE_DIR "/${CMAKE_INSTALL_LIBDIR}/cmake")
string(REPLACE ";" "${AWS_MODULE_DIR};" AWS_MODULE_PATH "${CMAKE_PREFIX_PATH}${AWS_MODULE_DIR}")
# Append that generated list to the module search path
list(APPEND CMAKE_MODULE_PATH ${AWS_MODULE_PATH})

include(AwsCFlags)
include(AwsCheckHeaders)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(AwsFindPackage)
include(CTest)

option(BUILD_RELOCATABLE_BINARIES
        "Build Relocatable Binaries, this will turn off features that will fail on older kernels than used for the build."
        OFF)
option(BYO_CRYPTO "Don't build a tls implementation or link against a crypto interface. This feature is only for unix builds currently."
        OFF)

file(GLOB AWS_IO_HEADERS
        "include/aws/io/*.h"
        )

file(GLOB AWS_IO_UV_HEADERS
        "include/aws/io/uv/*.h"
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

set(USE_S2N OFF)

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

         set(EVENT_LOOP_DEFINE "IO_COMPLETION_PORTS")
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
    set(PLATFORM_LIBS Secur32 Crypt32 Shlwapi)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    option(USE_VSOCK
	    "Build in support for VSOCK sockets"
	    OFF)

    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/linux/*.c"
            "source/posix/*.c"
            )
    set(PLATFORM_LIBS "")

    set(EVENT_LOOP_DEFINE "EPOLL")
    set(USE_S2N ON)

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
    list(APPEND PLATFORM_LIBS "-framework Security")
    set(EVENT_LOOP_DEFINE "KQUEUE")

elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/bsd/*.c"
            "source/posix/*.c"
            )

    set(EVENT_LOOP_DEFINE "KQUEUE")
    set(USE_S2N ON)

endif()

if (NOT BYO_CRYPTO AND USE_S2N)
    file(GLOB AWS_IO_TLS_SRC
            "source/s2n/*.c"
            )
    aws_use_package(s2n)
endif()

if (BYO_CRYPTO AND (APPLE OR WIN32))
    message(FATAL_ERROR "BYO_CRYPTO is only for use with unix systems. It cannot be used on your current platform target")
endif()

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

add_library(${PROJECT_NAME} ${LIBTYPE} ${IO_HEADERS} ${IO_SRC})
aws_set_common_properties(${PROJECT_NAME})
aws_prepare_symbol_visibility_args(${PROJECT_NAME} "AWS_IO")
aws_check_headers(${PROJECT_NAME} ${IO_HEADERS})

aws_add_sanitizers(${PROJECT_NAME})

# We are not ABI stable yet
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION 1.0.0)

target_compile_definitions(${PROJECT_NAME} PUBLIC "-DAWS_USE_${EVENT_LOOP_DEFINE}")

if (BYO_CRYPTO)
    target_compile_definitions(${PROJECT_NAME} PUBLIC "-DBYO_CRYPTO")
endif()

if (BUILD_RELOCATABLE_BINARIES)
    target_compile_definitions(${PROJECT_NAME} PRIVATE "-DCOMPAT_MODE")
endif()

if (USE_VSOCK)
	target_compile_definitions(${PROJECT_NAME} PUBLIC "-DUSE_VSOCK")
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

aws_use_package(aws-c-common)
aws_use_package(aws-c-cal)
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEP_AWS_LIBS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PLATFORM_LIBS})

aws_prepare_shared_lib_exports(${PROJECT_NAME})

install(FILES ${AWS_IO_HEADERS} DESTINATION "include/aws/io" COMPONENT Development)
install(FILES ${AWS_IO_TESTING_HEADERS} DESTINATION "include/aws/testing" COMPONENT Development)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/${TARGET_DIR}"
        NAMESPACE AWS::
        COMPONENT Development)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${LIBRARY_DIRECTORY}/${PROJECT_NAME}/cmake/"
        COMPONENT Development)

if (NOT CMAKE_CROSSCOMPILING)
    if (BUILD_TESTING)
       add_subdirectory(tests)
    endif()
endif()

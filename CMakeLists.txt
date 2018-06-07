cmake_minimum_required(VERSION 3.1)
project(aws-c-io)

option(BUILD_PORTABLE_BINARIES
        "Build Relocatable Binaries, this will turn off features that will fail on older kernels than used for the build."
        OFF)

file(GLOB AWS_IO_HEADERS
        "include/aws/io/*.h"
        )

file(GLOB AWS_IO_PRIV_HEADERS
        "include/aws/io/private/*.h"
        )

file(GLOB AWS_IO_SRC
        "source/*.c"
        )

if (WIN32)
    file(GLOB AWS_IO_OS_HEADERS
            )

    file(GLOB AWS_IO_OS_SRC
            "source/windows/*.c"
            )

    if (MSVC)
        source_group("Header Files\\aws\\io" FILES ${AWS_IO_HEADERS})
        source_group("Header Files\\aws\\io\\private" FILES ${AWS_IO_PRIV_HEADERS})
        source_group("Source Files" FILES ${AWS_IO_SRC})
        source_group("Source Files\\windows" FILES ${AWS_OS_SRC})
    endif ()
    #platform libs come from aws-c-common transitively, so we don't specify them here, but for documentation purposes,
    #Kernel32 and wsock2 are pulled in automatically. Here we add the lib containing the schannel API.
    #Also note, you don't get a choice on TLS implementation for Windows.
    set(PLATFORM_LIBS Secur32)
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
        set(PLATFORM_LIBS ${PlATFORM_LIBS} s2n)
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
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)

set(CMAKE_C_FLAGS_DEBUGOPT "")
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY C_STANDARD 99)

if (BUILD_SHARED_LIBS AND WIN32)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE "-DAWS_IO_EXPORTS")
    target_compile_definitions(${CMAKE_PROJECT_NAME} PUBLIC "-DUSE_IMPORT_EXPORT")
endif ()

if (BUILD_JNI_BINDINGS)
    set(BUILD_PORTABLE_BINARIES ON)
    find_package(JNI)
    include_directories(${JNI_INCLUDE_DIRS})
    set(PLATFORM_LIBS ${PLATFORM_LIBS} ${JNI_LIBRARIES})
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE "-DBUILD_JNI_BINDINGS")
endif ()

if (BUILD_PORTABLE_BINARIES)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE "-DCOMPAT_MODE")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE "-DDEBUG_BUILD")
endif ()

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

find_package(aws-c-common REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} aws-c-common ${PLATFORM_LIBS})

install(FILES ${AWS_IO_HEADERS} DESTINATION "include/aws/io")

install(
        TARGETS ${CMAKE_PROJECT_NAME} EXPORT ${CMAKE_PROJECT_NAME}-config
        ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
        COMPONENT library
)

export(TARGETS ${CMAKE_PROJECT_NAME} FILE ${CMAKE_PROJECT_NAME}-config.cmake)
install(EXPORT ${CMAKE_PROJECT_NAME}-config DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/${CMAKE_PROJECT_NAME}/cmake/")

include(CTest)
add_subdirectory(tests)

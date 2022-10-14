cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0115 NEW)

project(fleece)

find_package(PkgConfig REQUIRED)

pkg_check_modules( SSL REQUIRED libssl libcrypto )
include_directories( ${SSL_INCLUDE_DIRS} )
add_compile_options( ${SSL_CFLAGS} )

include(etc/build_type.cmake)
include(etc/cflags.cmake)
include(etc/clang_format.cmake)
include(etc/tests.cmake)

include_directories("${PROJECT_SOURCE_DIR}/src/util")

add_subdirectory("${PROJECT_SOURCE_DIR}/src/util")
add_subdirectory("${PROJECT_SOURCE_DIR}/src/frontend")


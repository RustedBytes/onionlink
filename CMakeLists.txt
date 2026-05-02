cmake_minimum_required(VERSION 3.20)

project(onionlink LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(MBEDTLS REQUIRED IMPORTED_TARGET mbedtls)
pkg_check_modules(MBEDX509 REQUIRED IMPORTED_TARGET mbedx509)
pkg_check_modules(MBEDCRYPTO REQUIRED IMPORTED_TARGET mbedcrypto)

add_executable(onionlink
    src/onionlink.cpp
)

target_compile_options(onionlink PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(onionlink PRIVATE
    PkgConfig::SODIUM
    PkgConfig::MBEDTLS
    PkgConfig::MBEDX509
    PkgConfig::MBEDCRYPTO
)

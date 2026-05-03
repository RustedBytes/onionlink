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

option(ONIONLINK_BUILD_CLI "Build the onionlink command line client" ON)
option(ONIONLINK_BUILD_PYTHON "Build Python bindings" OFF)

set(ONIONLINK_LIBS
    PkgConfig::SODIUM
    PkgConfig::MBEDTLS
    PkgConfig::MBEDX509
    PkgConfig::MBEDCRYPTO
)

if(ONIONLINK_BUILD_CLI)
    add_executable(onionlink
        src/onionlink.cpp
    )

    target_compile_options(onionlink PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(onionlink PRIVATE ${ONIONLINK_LIBS})
endif()

if(ONIONLINK_BUILD_PYTHON)
    set(PYBIND11_FINDPYTHON ON)
    find_package(pybind11 CONFIG REQUIRED)

    pybind11_add_module(_native MODULE
        src/onionlink_python.cpp
    )
    target_compile_options(_native PRIVATE -Wall -Wextra -Wpedantic)
    target_link_libraries(_native PRIVATE ${ONIONLINK_LIBS})
    install(TARGETS _native LIBRARY DESTINATION onionlink)
endif()

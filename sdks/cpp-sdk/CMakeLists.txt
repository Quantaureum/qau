# Quantaureum C++ SDK source, version 1.0.0.
cmake_minimum_required(VERSION 3.16)
project(quantaureum-sdk VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler security flags
if(MSVC)
    # MSVC warnings and security flags
    add_compile_options(/W4)
    add_compile_options(/sdl)  # Security Development Lifecycle checks
    add_compile_options(/GS)   # Buffer security check
    add_compile_options(/guard:cf)  # Control Flow Guard
else()
    # GCC/Clang warnings
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options(-Wformat=2 -Wformat-security)
    add_compile_options(-Wconversion -Wsign-conversion)
    add_compile_options(-Werror=format-security)

    # Stack protection
    add_compile_options(-fstack-protector-strong)

    # Position Independent Code
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Debug build: Enable sanitizers
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(STATUS "Debug build: Enabling AddressSanitizer and UndefinedBehaviorSanitizer")
        add_compile_options(-fsanitize=address -fsanitize=undefined)
        add_compile_options(-fno-omit-frame-pointer)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
endif()

# Options
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_EXAMPLES "Build examples" OFF)

# Dependencies via FetchContent
include(FetchContent)

# nlohmann/json - use single header
set(JSON_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann")
if(NOT EXISTS "${JSON_HEADER_DIR}/json.hpp")
    file(MAKE_DIRECTORY "${JSON_HEADER_DIR}")
    message(STATUS "Downloading nlohmann/json single header...")
    file(DOWNLOAD
        "https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp"
        "${JSON_HEADER_DIR}/json.hpp"
        TIMEOUT 60
        STATUS DOWNLOAD_STATUS
    )
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(WARNING "Failed to download json.hpp, will try to use system package")
    endif()
endif()

# Create interface library for json
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

# Find system packages (optional for now)
find_package(CURL QUIET)
find_package(OpenSSL QUIET)

if(NOT CURL_FOUND)
    message(STATUS "CURL not found - Client module will not be available")
endif()
if(NOT OPENSSL_FOUND)
    message(STATUS "OpenSSL not found - using simplified crypto")
endif()

# Try to find libsecp256k1
find_library(SECP256K1_LIBRARY NAMES secp256k1 libsecp256k1)
find_path(SECP256K1_INCLUDE_DIR NAMES secp256k1.h)

# Check in third_party directory first
if(NOT SECP256K1_LIBRARY OR NOT SECP256K1_INCLUDE_DIR)
    set(SECP256K1_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1/build/lib/Release/libsecp256k1.lib")
    set(SECP256K1_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1/include")
    set(SECP256K1_DLL "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1/build/bin/Release/libsecp256k1-6.dll")
endif()

if(EXISTS "${SECP256K1_LIBRARY}" AND EXISTS "${SECP256K1_INCLUDE_DIR}")
    message(STATUS "Found libsecp256k1: ${SECP256K1_LIBRARY}")
    message(STATUS "Found libsecp256k1 DLL: ${SECP256K1_DLL}")
    set(SECP256K1_FOUND TRUE)
else()
    message(WARNING "libsecp256k1 not found - ECDSA operations will not work")
    message(WARNING "Install libsecp256k1 from: https://github.com/bitcoin-core/secp256k1")
    set(SECP256K1_FOUND FALSE)
endif()

# Library sources
set(QUANTAUREUM_SOURCES
    src/types/address.cpp
    src/types/hash.cpp
    src/types/uint256.cpp
    src/types/transaction.cpp
    src/types/log.cpp
    src/utils/hex.cpp
    src/utils/keccak256.cpp
    src/utils/sha256.cpp
    src/utils/convert.cpp
    src/utils/secure_random.cpp
    src/utils/key_derivation.cpp
    src/crypto/ecdsa.cpp
    src/crypto/bip39.cpp
    src/crypto/bip32.cpp
    src/account.cpp
    src/abi.cpp
    src/client.cpp
)

# Main library
add_library(quantaureum ${QUANTAUREUM_SOURCES})
target_include_directories(quantaureum PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(quantaureum
    PRIVATE $<$<BOOL:${CURL_FOUND}>:CURL::libcurl>
    PRIVATE $<$<BOOL:${OPENSSL_FOUND}>:OpenSSL::SSL>
    PRIVATE $<$<BOOL:${OPENSSL_FOUND}>:OpenSSL::Crypto>
    PRIVATE $<$<BOOL:${SECP256K1_FOUND}>:${SECP256K1_LIBRARY}>
)

# Add secp256k1 include directory if found
if(SECP256K1_FOUND)
    target_include_directories(quantaureum PRIVATE ${SECP256K1_INCLUDE_DIR})
    target_compile_definitions(quantaureum PRIVATE HAVE_SECP256K1)
endif()

# Link WinHTTP on Windows
if(WIN32)
    target_link_libraries(quantaureum PRIVATE winhttp)
endif()


# Tests
if(BUILD_TESTS)
    enable_testing()

    # Google Test - use local copy
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(third_party/googletest/googletest-1.14.0)

    # RapidCheck for property-based testing - use local copy
    set(RC_ENABLE_GTEST ON CACHE BOOL "" FORCE)
    add_subdirectory(third_party/rapidcheck/rapidcheck-master)

    # Test executable
    add_executable(quantaureum_tests
        tests/test_hex.cpp
        tests/test_address.cpp
        tests/test_keccak256.cpp
        tests/test_convert.cpp
        tests/test_account.cpp
        tests/test_abi.cpp
        tests/test_secure_random.cpp
        tests/test_key_derivation.cpp
        tests/test_secure_memory.cpp
        tests/test_sha256.cpp
        tests/test_bip39.cpp
        tests/test_bip32.cpp
        tests/test_ecdsa.cpp
    )
    target_include_directories(quantaureum_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/rapidcheck/rapidcheck-master/extras/gtest/include
    )
    target_link_libraries(quantaureum_tests
        quantaureum
        GTest::gtest_main
        rapidcheck
    )

    include(GoogleTest)
    gtest_discover_tests(quantaureum_tests)
endif()

# Installation
install(TARGETS quantaureum
    EXPORT quantaureum-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT quantaureum-targets
    FILE quantaureum-config.cmake
    NAMESPACE quantaureum::
    DESTINATION lib/cmake/quantaureum
)

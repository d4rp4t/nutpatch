# IDE support + tests — NOT used for Android or iOS builds.

cmake_minimum_required(VERSION 3.9.0)
project(NitroNutpatch)

set(CMAKE_CXX_STANDARD 20)

set(NODE_MODULES "${CMAKE_CURRENT_SOURCE_DIR}/node_modules")
set(NITRO_CPP "${NODE_MODULES}/react-native-nitro-modules/cpp")

# secp256k1
add_library(secp256k1 STATIC
  cpp/vendor/secp256k1/src/secp256k1.c
  cpp/vendor/secp256k1/src/precomputed_ecmult.c
  cpp/vendor/secp256k1/src/precomputed_ecmult_gen.c
)
target_include_directories(secp256k1 PUBLIC
  cpp/vendor/secp256k1/include
  cpp/vendor/secp256k1/src
  cpp/vendor/secp256k1
)
target_compile_definitions(secp256k1 PRIVATE
  SECP256K1_STATIC=1
  ENABLE_MODULE_EXTRAKEYS=1
  ENABLE_MODULE_SCHNORRSIG=1
)

# trezor crypto (HMAC-SHA256/512 for NUT-13 deterministic derivation)
add_library(trezor_crypto STATIC
  cpp/vendor/trezor/sha2.c
  cpp/vendor/trezor/hmac.c
  cpp/vendor/trezor/memzero.c
)
target_include_directories(trezor_crypto PUBLIC cpp/vendor/trezor)

# Portable crypto core (no NitroModules / JSI dependency).
# Split out so host-side unit tests can link it without pulling RN headers.
add_library(crypto_core STATIC
  cpp/core/crypto.c
)
target_include_directories(crypto_core PUBLIC
  cpp/core
  cpp/vendor/secp256k1/include
  cpp/vendor/trezor
)
target_link_libraries(crypto_core PUBLIC secp256k1 trezor_crypto)

# Main (IDE indexing only — no prefab/Gradle deps)
add_library(NitroNutpatch SHARED
  cpp/core/HybridOutputCreator.cpp
)

# <NitroModules/...> resolves when NitroModules/ symlink → cpp/core exists
if(NOT EXISTS "${NITRO_CPP}/NitroModules")
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink core "${NITRO_CPP}/NitroModules")
endif()

target_include_directories(NitroNutpatch PRIVATE
  nitrogen/generated/shared/c++
  # NitroModules core headers
  ${NITRO_CPP}
  ${NITRO_CPP}/core
  ${NITRO_CPP}/jsi
  ${NITRO_CPP}/utils
  ${NITRO_CPP}/platform
  ${NITRO_CPP}/prototype
  ${NITRO_CPP}/threading
)

target_link_libraries(NitroNutpatch crypto_core)

option(NUTPATCH_BUILD_TESTS "Build C++ unit tests" ON)
if(NUTPATCH_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  enable_testing()

  add_executable(nutpatch_tests
    cpp/tests/crypto_test.cpp
  )
  target_link_libraries(nutpatch_tests PRIVATE crypto_core GTest::gtest_main)

  include(GoogleTest)
  gtest_discover_tests(nutpatch_tests)
endif()

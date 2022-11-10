# Copyright (c) 2022 Intel Corporation
# Copyright (c) 2020-2021 Alibaba Cloud
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (LIB_RATS_DIR ${CMAKE_CURRENT_LIST_DIR})
set (SGX_SDK_INCLUDE_DIR "/opt/intel/sgxsdk/include")
set (SGX_SSL_INCLUDE_DIR "/opt/intel/sgxssl/include")

if (NOT EXISTS ${SGX_SDK_INCLUDE_DIR})
    message(FATAL_ERROR "Can not find SGX_SDK, please install it first")
endif()

if (NOT EXISTS ${SGX_SSL_INCLUDE_DIR})
    message(FATAL_ERROR "Can not find SGX_SSL, please install it first")
endif()

add_definitions (-DWASM_ENABLE_LIB_RATS=1)

include_directories(${LIB_RATS_DIR} ${SGX_SDK_INCLUDE_DIR} ${SGX_SSL_INCLUDE_DIR})

include(FetchContent)

set(RATS_BUILD_MODE "sgx"
    CACHE INTERNAL "Select build mode for librats(host|occlum|sgx｜wasm)")
set(RATS_INSTALL_PATH  "${CMAKE_BINARY_DIR}/librats" CACHE INTERNAL "")

FetchContent_Declare(
    librats
    GIT_REPOSITORY https://github.com/inclavare-containers/librats
    GIT_TAG master
)
FetchContent_GetProperties(librats)
if (NOT librats_POPULATED)
    message("-- Fetching librats ..")
    FetchContent_Populate(librats)
    include_directories("${librats_SOURCE_DIR}/include")
    add_subdirectory(${librats_SOURCE_DIR} ${librats_BINARY_DIR} EXCLUDE_FROM_ALL)

endif()

file (GLOB source_all ${LIB_RATS_DIR}/*.c)

set (LIB_RATS_SOURCE ${source_all})
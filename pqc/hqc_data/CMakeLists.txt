# Builds the HQC data-generation programs against the official HQC v5.0.0
# sources, which must be downloaded into pqc/hqc_data/hqc-v5.0.0 (see
# README.md).
#   build/hqc_test           PKE encryptions     (datagen/data_generation.py)
#   build/hqc_kem            KEM encapsulations  (datagen/xor_bce_data.py)
#   build/inspect_hqc_files  debug utility
cmake_minimum_required(VERSION 3.21)
project(hqc_test_program VERSION 1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build type defaults to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compilation flags
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -Wall -Werror -Wextra -Wmissing-prototypes -Wpedantic")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g -Wall -Werror -Wextra -Wmissing-prototypes -Wpedantic")

# Set HQC_ARCH and variant
set(HQC_ARCH "ref" CACHE STRING "Choose implementation: ref or x86_64")
set(HQC_VARIANT "hqc-5" CACHE STRING "Choose variant: hqc-1, hqc-3, or hqc-5")
set(HQC_VARIANT_SAFE "hqc_5")  # Safe version for target names

# Set up source directories
set(HQC_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/hqc-v5.0.0/src")
set(HQC_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/hqc-v5.0.0/lib")

# Collect HQC source files
file(GLOB_RECURSE HQC_COMMON_SRCS
    "${HQC_SRC_DIR}/common/*.c"
)

# Collect architecture-specific source files and set include dirs
if(HQC_ARCH STREQUAL "x86_64")
    # x86_64 layout: avx256/{*.c,<variant>/*.c} + common/{*.c,<variant>/*.c}
    set(HQC_AVX_DIR  "${HQC_SRC_DIR}/x86_64/avx256")
    set(HQC_CMN_DIR  "${HQC_SRC_DIR}/x86_64/common")
    file(GLOB HQC_ARCH_SRCS
        "${HQC_AVX_DIR}/*.c"
        "${HQC_CMN_DIR}/*.c"
    )
    file(GLOB HQC_VARIANT_SRCS
        "${HQC_AVX_DIR}/${HQC_VARIANT}/*.c"
        "${HQC_CMN_DIR}/${HQC_VARIANT}/*.c"
    )
    set(HQC_IMPL_INCLUDE_DIRS
        ${HQC_AVX_DIR}
        ${HQC_AVX_DIR}/${HQC_VARIANT}
        ${HQC_CMN_DIR}
        ${HQC_CMN_DIR}/${HQC_VARIANT}
    )
else()
    # ref layout: ref/{*.c} + ref/<variant>/*.c
    file(GLOB HQC_ARCH_SRCS    "${HQC_SRC_DIR}/ref/*.c")
    file(GLOB HQC_VARIANT_SRCS "${HQC_SRC_DIR}/ref/${HQC_VARIANT}/*.c")
    set(HQC_IMPL_INCLUDE_DIRS
        ${HQC_SRC_DIR}/ref
        ${HQC_SRC_DIR}/ref/${HQC_VARIANT}
    )
endif()

# Collect fips202 library sources
file(GLOB_RECURSE FIPS202_SRCS
    "${HQC_LIB_DIR}/fips202/*.c"
)

# Create HQC library
add_library(hqc_lib STATIC
    ${HQC_COMMON_SRCS}
    ${HQC_ARCH_SRCS}
    ${HQC_VARIANT_SRCS}
    ${FIPS202_SRCS}
)

# Set library compile options
if(HQC_ARCH STREQUAL "ref")
    target_compile_definitions(hqc_lib PRIVATE HQC_ARCH_REF=1)
else()
    target_compile_definitions(hqc_lib PRIVATE HQC_ARCH_X86_64=1 HQC_ARCH_X86_64_AVX256=1)
endif()

# Include directories for the library
target_include_directories(hqc_lib PUBLIC
    ${HQC_SRC_DIR}/common
    ${HQC_SRC_DIR}/common/${HQC_VARIANT}
    ${HQC_IMPL_INCLUDE_DIRS}
    ${HQC_LIB_DIR}/fips202
    ${HQC_LIB_DIR}/nist-rng
)

# Create test program executable
add_executable(hqc_test hqc_test_program.c)

# Link against HQC library
target_link_libraries(hqc_test PRIVATE hqc_lib)

# Create KEM encapsulation program executable
add_executable(hqc_kem hqc_kem_program.c)

# Link against HQC library
target_link_libraries(hqc_kem PRIVATE hqc_lib)

# Create inspection utility (doesn't need HQC library)
add_executable(inspect_hqc_files inspect_hqc_files.c)

# Include directories for test program (inherits PUBLIC dirs from hqc_lib via link)
target_include_directories(hqc_test PRIVATE
    ${HQC_SRC_DIR}
)

# Include directories for KEM program (inherits PUBLIC dirs from hqc_lib via link)
target_include_directories(hqc_kem PRIVATE
    ${HQC_SRC_DIR}
)

# Installation (optional)
install(TARGETS hqc_test hqc_kem DESTINATION bin)

# Print configuration summary
message(STATUS "====== HQC Test Program Configuration ======")
message(STATUS "HQC Architecture:  ${HQC_ARCH}")
message(STATUS "HQC Variant:       ${HQC_VARIANT}")
message(STATUS "Build Type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "Build Command:     cmake --build <build-dir>")
message(STATUS "Run Command:       ./hqc_test <N> <output_base>")
message(STATUS "============================================")

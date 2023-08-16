#
# Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
#
# SPDX-License-Identifier: BSD-2-Clause
#

cmake_minimum_required(VERSION 3.7.2)

project(libsel4allocman C)

set(configure_string "")

config_option(
    LibAllocmanAllowPoolOperations
    LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS
    "Memory pool (pre-allocated objects) enable libsel4allocman to \
    perform frame object pre-allocation, which is beneficial to \
    the implementation of CapBuddy on top of seL4 micro-kernel."
    DEFAULT
    OFF
)

config_option(
    LibAllocmanDebug
    LIB_ALLOCMAN_DEBUG
    ""
    DEFAULT
    OFF
)

config_option(
    LibAllocmanSplitCapBuddyEnable
    LIB_ALLOCMAN_SPLIT_CAPBUDDY_ENABLE
    "Cut large untyped objects into 4M pieces during untyped adding \
    procedure when bootstrapping allocman utspace 'split' allocator \
    to enjoy CapBuddy support -> stop using the split-based CapBuddy."
    DEFAULT
    OFF
)

mark_as_advanced(LibAllocmanAllowPoolOperations LibAllocmanDebug)
add_config_library(sel4allocman "${configure_string}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

file(
    GLOB
        deps
        src/*.c
        src/cspace/*.c
        src/utspace/*.c
        src/mspace/*.c
)

list(SORT deps)

add_library(sel4allocman STATIC EXCLUDE_FROM_ALL ${deps})
target_include_directories(sel4allocman PUBLIC include "sel4_arch/${KernelSel4Arch}")
target_include_directories(sel4allocman PUBLIC include "arch/${KernelArch}")
target_link_libraries(
    sel4allocman
    PUBLIC
        muslc
        sel4
        sel4vka
        sel4utils
        sel4vspace
        sel4_autoconf
        sel4allocman_Config
)

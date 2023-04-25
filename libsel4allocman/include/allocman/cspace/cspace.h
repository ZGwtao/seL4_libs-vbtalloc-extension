/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/types.h>
#include <sel4allocman/gen_config.h>
#include <allocman/properties.h>
#include <vka/cspacepath_t.h>
#include <stddef.h>

struct allocman;

typedef struct cspace_interface {
    int (*alloc)(struct allocman *alloc, void *cookie, cspacepath_t *path);
#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS
    int (*csa)(struct allocman *alloc, void *cookie, cspacepath_t *path, size_t num_bits);
    int (*pool)(struct allocman *alloc, void *_cspace, seL4_CPtr slot);
#endif
    void (*free)(struct allocman *alloc, void *cookie, const cspacepath_t *path);
    cspacepath_t (*make_path)(void *cookie, seL4_CPtr slot);
    struct allocman_properties properties;
    void *cspace;
} cspace_interface_t;

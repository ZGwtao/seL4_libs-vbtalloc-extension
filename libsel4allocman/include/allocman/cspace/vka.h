/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <autoconf.h>
#include <sel4/types.h>
#include <allocman/cspace/cspace.h>
#include <vka/vka.h>

/* This is a proxy allocator that just passes any allocs/frees to a vka interface */
static inline cspacepath_t _cspace_vka_make_path(void *_cspace, seL4_CPtr slot)
{
    vka_t *vka = (vka_t*)_cspace;
    cspacepath_t path;
    vka_cspace_make_path(vka, slot, &path);
    return path;
}

static int _cspace_vka_alloc(struct allocman *alloc, void *_cspace, cspacepath_t *slot)
{
    vka_t *vka = (vka_t*)_cspace;
    (void)alloc;
    return vka_cspace_alloc_path(vka, slot);
}
static void _cspace_vka_free(struct allocman *alloc, void *_cspace, const cspacepath_t *slot)
{
    vka_t *vka = (vka_t*)_cspace;
    (void)alloc;
    vka_cspace_free(vka, slot->capPtr);
}

/**
 * Make a cspace interface from a VKA. It is the responsibility of the caller to ensure
 * that this pointer remains valid for as long as this cspace is used
 *
 * @param vka Allocator to proxy cspace calls to
 * @return cspace_interface that can be given to allocman
 */
static inline struct cspace_interface cspace_vka_make_interface(vka_t *vka) {
    return (struct cspace_interface){
        .alloc = _cspace_vka_alloc,
        .free = _cspace_vka_free,
        .make_path = _cspace_vka_make_path,
#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS
        .pool = NULL,
        .csa = NULL,
#endif
        /* VKA is not guaranteed to recurse */
        .properties = ALLOCMAN_DEFAULT_PROPERTIES,
        .cspace = vka
    };
}


/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <allocman/allocman.h>
#include <allocman/util.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sel4/sel4.h>
#include <allocman/vka.h>
#include <vka/object.h>
#include <allocman/cspace/vka.h>
#include <allocman/utspace/vka.h>
#include <allocman/mspace/malloc.h>
#include <kernel/gen_config.h>

/**
 * Allocate a slot in a cspace.
 *
 * @param data cookie for the underlying allocator
 * @param res pointer to a cptr to store the allocated slot
 * @return 0 on success
 */
static int am_vka_cspace_alloc(void *data, seL4_CPtr *res)
{
    int error;
    cspacepath_t path;

    assert(data);
    assert(res);

    error = allocman_cspace_alloc((allocman_t *) data, &path);
    if (!error) {
        *res = path.capPtr;
    }

    return error;
}

/**
 * Convert an allocated cptr to a cspacepath, for use in
 * operations such as Untyped_Retype
 *
 * @param data cookie for the underlying allocator
 * @param slot a cslot allocated by the cspace alloc function
 * @param res pointer to a cspacepath struct to fill out
 */
static void am_vka_cspace_make_path (void *data, seL4_CPtr slot, cspacepath_t *res)
{
    assert(data);
    assert(res);

    *res = allocman_cspace_make_path((allocman_t*) data, slot);
}

/**
 * Free an allocated cslot
 *
 * @param data cookie for the underlying allocator
 * @param slot a cslot allocated by the cspace alloc function
 */
static void am_vka_cspace_free (void *data, seL4_CPtr slot)
{
    cspacepath_t path;
    assert(data);
    path = allocman_cspace_make_path((allocman_t*)data, slot);

    allocman_cspace_free((allocman_t *) data, &path);
}

/**
 * Allocate a portion of an untyped into an object
 *
 * @param data cookie for the underlying allocator
 * @param dest path to an empty cslot to place the cap to the allocated object
 * @param type the seL4 object type to allocate (as passed to Untyped_Retype)
 * @param size_bits the size of the object to allocate (as passed to Untyped_Retype)
 * @param can_use_dev whether the allocator can use device untyped instead of regular untyped
 * @param res pointer to a location to store the cookie representing this allocation
 * @return 0 on success
 */
static int am_vka_utspace_alloc_maybe_device (void *data, const cspacepath_t *dest,
                seL4_Word type, seL4_Word size_bits, bool can_use_dev, seL4_Word *res)
{
    int error;

    assert(data);
    assert(res);
    assert(dest);

    /* allocman uses the size in memory internally, where as vka expects size_bits
     * as passed to Untyped_Retype, so do a conversion here */
    size_bits = vka_get_object_size(type, size_bits);

    *res = allocman_utspace_alloc((allocman_t *) data, size_bits, type, (cspacepath_t*)dest, can_use_dev, &error);

    return error;
}

/**
 * Allocate a portion of an untyped into an object
 *
 * @param data cookie for the underlying allocator
 * @param dest path to an empty cslot to place the cap to the allocated object
 * @param type the seL4 object type to allocate (as passed to Untyped_Retype)
 * @param size_bits the size of the object to allocate (as passed to Untyped_Retype)
 * @param res pointer to a location to store the cookie representing this allocation
 * @return 0 on success
 */
static int am_vka_utspace_alloc (void *data, const cspacepath_t *dest, seL4_Word type, seL4_Word size_bits, seL4_Word *res)
{
    return am_vka_utspace_alloc_maybe_device(data, dest, type, size_bits, false, res);
}

/**
 * Allocate a portion of an untyped into an object
 *
 * @param data cookie for the underlying allocator
 * @param dest path to an empty cslot to place the cap to the allocated object
 * @param type the seL4 object type to allocate (as passed to Untyped_Retype)
 * @param size_bits the size of the object to allocate (as passed to Untyped_Retype)
 * @param paddr the desired physical address of the start of the allocated object
 * @param res pointer to a location to store the cookie representing this allocation
 * @return 0 on success
 */
static int am_vka_utspace_alloc_at (void *data, const cspacepath_t *dest, seL4_Word type, seL4_Word size_bits, uintptr_t paddr, seL4_Word *res)
{
    int error;

    assert(data);
    assert(res);
    assert(dest);

    /* allocman uses the size in memory internally, where as vka expects size_bits
     * as passed to Untyped_Retype, so do a conversion here */
    size_bits = vka_get_object_size(type, size_bits);

#if CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS /* CapBuddy support */
    /***
     * CBD:
     * We may implement CapBuddy support for typical physical address from here.
     * To make it sure that it works, we now only support single-page allocation.
     * FIXME:
     * Maybe we should not implement CapBuddy in here, as it has imported extra
     * system call overhead (for copying the capability of a frame from CapBuddy
     * memory pool to the already allocated, which could have been assigned with
     * the capability of target frame, destination cslot)
     */
    if (type == kobject_get_type(KOBJECT_FRAME, size_bits)) {
        cspacepath_t temp_dest;
        /* single page allocation is provided only */
        assert(size_bits == seL4_PageBits);
        error = allocman_utspace_try_alloc_from_pool(data, size_bits, paddr, false, &temp_dest);
        if (error == seL4_NoError) {
            /* destination cslot is constant value */
            /* Is it possible to remove this system call? */
            error = seL4_CNode_Copy(
                        dest->root,
                        dest->capPtr,
                        dest->capDepth,
                        temp_dest.root,
                        temp_dest.capPtr,
                        temp_dest.capDepth,
                        seL4_AllRights
                    );
            if (error != seL4_NoError) {
                ZF_LOGE("Failed to copy cap of frame from CapBuddy to destination cslot");
            } else {
                /***
                 * FIXME:
                 * No return cookie for the allocated object (the original untyped object ?)
                 * 'cptr' is enough for its deallocation. (But maybe in the future we should
                 * try to recycle all allocated but unused untyped object of a virtual-bitmap-tree ?)
                 */
                *res = 0x0;
            }
            return error;
        }
        /* If we can't allocated from a virtual-bitmap-tree, giving it up now. */
    }
#endif
    *res = allocman_utspace_alloc_at((allocman_t *) data, size_bits, type, (cspacepath_t*)dest, paddr, true, &error);

    return error;
}

/**
 * Free a portion of an allocated untyped. Is the responsibility of the caller to
 * have already deleted the object (by deleting all capabilities) first
 *
 * @param data cookie for the underlying allocator
 * @param type the seL4 object type that was allocated (as passed to Untyped_Retype)
 * @param size_bits the size of the object that was allocated (as passed to Untyped_Retype)
 * @param target cookie to the allocation as given by the utspace alloc function
 */
static void am_vka_utspace_free (void *data, seL4_Word type, seL4_Word size_bits, seL4_Word target)
{
    assert(data);

    /* allocman uses the size in memory internally, where as vka expects size_bits
     * as passed to Untyped_Retype, so do a conversion here */
    size_bits = vka_get_object_size(type, size_bits);

    allocman_utspace_free((allocman_t *)data, target, size_bits);
}

static uintptr_t am_vka_utspace_paddr (void *data, seL4_Word target, seL4_Word type, seL4_Word size_bits)
{
    assert(data);

    /* allocman uses the size in memory internally, where as vka expects size_bits
     * as passed to Untyped_Retype, so do a conversion here */
    size_bits = vka_get_object_size(type, size_bits);

    return allocman_utspace_paddr((allocman_t *)data, target, size_bits);
}

#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS

static int am_vka_utspace_try_alloc_from_pool(void *data, seL4_Word size_bits, uintptr_t paddr, bool can_use_dev, cspacepath_t *res)
{
    assert(data);
    assert(res);

    if (seL4_PageBits != size_bits) {
        if (size_bits < seL4_PageBits || size_bits > (seL4_PageBits + 10)) {
            return -1;
        }
    }
    return allocman_utspace_try_alloc_from_pool((allocman_t *)data, size_bits, paddr, can_use_dev, res);
}

static void am_vka_utspace_try_free_from_pool(void *data, seL4_CPtr cptr, size_t num_bits)
{
    assert(data);
    allocman_utspace_try_free_from_pool((allocman_t *)data, cptr, num_bits);
}

static int am_vka_cspace_is_from_pool(void *data, seL4_CPtr cptr, size_t num_bits)
{
    assert(data);
    /***
     * @param: cptr : target capability pointer (to be determined
     *  if it's allocated from the memory pool of CapBuddy or not)
     */
    return allocman_cspace_target_object_allocated_from_pool((allocman_t *)data, cptr, num_bits);
}

#endif

/**
 * Make a VKA object using this allocman
 *
 * @param structure for the vka interface object
 * @param allocator to be used with this vka
 */
void allocman_make_vka(vka_t *vka, allocman_t *alloc)
{
    assert(vka);
    assert(alloc);

    vka->data = alloc;
    vka->cspace_alloc = &am_vka_cspace_alloc;
    vka->cspace_make_path = &am_vka_cspace_make_path;
    vka->utspace_alloc = &am_vka_utspace_alloc;
    vka->utspace_alloc_maybe_device = &am_vka_utspace_alloc_maybe_device;
    vka->utspace_alloc_at = &am_vka_utspace_alloc_at;
    vka->cspace_free = &am_vka_cspace_free;
    vka->utspace_free = &am_vka_utspace_free;
    vka->utspace_paddr = &am_vka_utspace_paddr;

#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS

    vka->utspace_try_alloc_from_pool = &am_vka_utspace_try_alloc_from_pool;
    vka->utspace_try_free_from_pool = &am_vka_utspace_try_free_from_pool;
    vka->cspace_is_from_pool = &am_vka_cspace_is_from_pool;

#endif

}

int allocman_make_from_vka(vka_t *vka, allocman_t *alloc)
{
    int error;
    assert(vka);
    assert(alloc);

    error = allocman_create(alloc, mspace_malloc_interface);
    if (error) {
        return error;
    }
    error = allocman_attach_utspace(alloc, utspace_vka_make_interface(vka));
    assert(!error);
    error = allocman_attach_cspace(alloc, cspace_vka_make_interface(vka));
    assert(!error);
    return 0;
}

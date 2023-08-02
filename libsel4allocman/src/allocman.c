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
#include <vka/capops.h>
#include <sel4utils/util.h>

static int _refill_watermark(allocman_t *alloc);

static inline int _can_alloc(struct allocman_properties properties, size_t alloc_depth, size_t free_depth)
{
    int in_alloc = alloc_depth > 0;
    int in_free = free_depth > 0;
    return (properties.alloc_can_alloc || !in_alloc) && (properties.free_can_alloc || !in_free);
}

static inline int _can_free(struct allocman_properties properties, size_t alloc_depth, size_t free_depth)
{
    int in_alloc = alloc_depth > 0;
    int in_free = free_depth > 0;
    return (properties.alloc_can_free || !in_alloc) && (properties.free_can_free || !in_free);
}

/* Signals an operation is being started, and returns whether
   this is the root operation, or a dependent call */
static int _start_operation(allocman_t *alloc)
{
    int ret = !alloc->in_operation;
    alloc->in_operation = 1;
    return ret;
}

static inline void _end_operation(allocman_t *alloc, int root)
{
    alloc->in_operation = !root;
    /* Anytime we end an operation we need to make sure we have watermark
       resources */
    if (root) {
        _refill_watermark(alloc);
    }
}

static void allocman_mspace_queue_for_free(allocman_t *alloc, void *ptr, size_t bytes) {
    if (alloc->num_freed_mspace_chunks == alloc->desired_freed_mspace_chunks) {
        assert(!"Out of space to store free'd objects. Leaking memory");
        return;
    }
    alloc->freed_mspace_chunks[alloc->num_freed_mspace_chunks] =
        (struct allocman_freed_mspace_chunk) {ptr, bytes};
    alloc->num_freed_mspace_chunks++;
}

static void allocman_cspace_queue_for_free(allocman_t *alloc, const cspacepath_t *path) {
    if (alloc->num_freed_slots == alloc->desired_freed_slots) {
        assert(!"Out of space to store free'd objects. Leaking memory");
        return;
    }
    alloc->freed_slots[alloc->num_freed_slots] = *path;
    alloc->num_freed_slots++;
}

static void allocman_utspace_queue_for_free(allocman_t *alloc, seL4_Word cookie, size_t size_bits) {
    if (alloc->num_freed_utspace_chunks == alloc->desired_freed_utspace_chunks) {
        assert(!"Out of space to store free'd objects. Leaking memory");
        return;
    }
    alloc->freed_utspace_chunks[alloc->num_freed_utspace_chunks] =
        (struct allocman_freed_utspace_chunk) {size_bits, cookie};
    alloc->num_freed_utspace_chunks++;
}

/* this nasty macro prevents code duplication for the free functions. Unfortunately I can think of no other
 * way of allowing the number of arguments to the 'free' function in the body to be parameterized */
#define ALLOCMAN_FREE(alloc,space,...) do { \
    int root; \
    assert(alloc->have_##space); \
    if (!_can_free(alloc->space.properties, alloc->space##_alloc_depth, alloc->space##_free_depth)) { \
        allocman_##space##_queue_for_free(alloc, __VA_ARGS__); \
        return; \
    } \
    root = _start_operation(alloc); \
    alloc->space##_free_depth++; \
    alloc->space.free(alloc, alloc->space.space, __VA_ARGS__); \
    alloc->space##_free_depth--; \
    _end_operation(alloc, root); \
} while(0)

void allocman_cspace_free(allocman_t *alloc, const cspacepath_t *slot)
{
    ALLOCMAN_FREE(alloc, cspace, slot);
}

void allocman_mspace_free(allocman_t *alloc, void *ptr, size_t bytes)
{
    ALLOCMAN_FREE(alloc, mspace, ptr, bytes);
}

void allocman_utspace_free(allocman_t *alloc, seL4_Word cookie, size_t size_bits)
{
    ALLOCMAN_FREE(alloc, utspace, cookie, size_bits);
}

static void *_try_watermark_mspace(allocman_t *alloc, size_t size, int *_error)
{
    size_t i;
    for (i = 0; i < alloc->num_mspace_chunks; i++) {
        if (alloc->mspace_chunk[i].size == size) {
            if (alloc->mspace_chunk_count[i] > 0) {
                void *ret = alloc->mspace_chunks[i][--alloc->mspace_chunk_count[i]];
                SET_ERROR(_error, 0);
                alloc->used_watermark = 1;
                return ret;
            }
        }
    }
    SET_ERROR(_error, 1);
    return NULL;
}

static int _try_watermark_cspace(allocman_t *alloc, cspacepath_t *slot)
{
    if (alloc->num_cspace_slots == 0) {
        return 1;
    }
    alloc->used_watermark = 1;
    *slot = alloc->cspace_slots[--alloc->num_cspace_slots];
    return 0;
}

static seL4_Word _try_watermark_utspace(allocman_t *alloc, size_t size_bits, seL4_Word type, const cspacepath_t *path, int *_error)
{
    size_t i;

    for (i = 0; i < alloc->num_utspace_chunks; i++) {
        if (alloc->utspace_chunk[i].size_bits == size_bits && alloc->utspace_chunk[i].type == type) {
            if (alloc->utspace_chunk_count[i] > 0) {
                struct allocman_utspace_allocation result = alloc->utspace_chunks[i][alloc->utspace_chunk_count[i] - 1];
                int error;
                /* Need to perform a cap move */
                error = vka_cnode_move(path, &result.slot);
                if (error != seL4_NoError) {
                    SET_ERROR(_error, 1);
                    return 0;
                }
                alloc->used_watermark = 1;
                alloc->utspace_chunk_count[i]--;
                allocman_cspace_free(alloc, &result.slot);
                SET_ERROR(_error, 0);
                return result.cookie;
            }
        }
    }
    SET_ERROR(_error, 1);
    return 0;
}

static void *_allocman_mspace_alloc(allocman_t *alloc, size_t size, int *_error, int use_watermark)
{
    int root_op;
    void *ret;
    int error;
    /* see if we have an allocator installed yet*/
    if (!alloc->have_mspace) {
        SET_ERROR(_error, 1);
        return 0;
    }
    /* Check that we are permitted to cspace_alloc here */
    if (!_can_alloc(alloc->mspace.properties, alloc->mspace_alloc_depth, alloc->mspace_free_depth)) {
        if (use_watermark) {
            ret = _try_watermark_mspace(alloc, size, _error);
            if (!ret) {
                ZF_LOGI("Failed to fullfill recursive allocation from watermark, size %zu\n", size);
            }
            return ret;
        } else {
            SET_ERROR(_error, 1);
            return 0;
        }
    }
    root_op = _start_operation(alloc);
    /* Attempt the allocation */
    alloc->mspace_alloc_depth++;
    ret = alloc->mspace.alloc(alloc, alloc->mspace.mspace, size, &error);
    alloc->mspace_alloc_depth--;
    if (!error) {
        _end_operation(alloc, root_op);
        SET_ERROR(_error, 0);
        return ret;
    }
    /* We encountered some fail. We will try and allocate from the watermark pool.
       Does not matter what the error or outcome is, just propogate back up*/
    if (use_watermark) {
        ret = _try_watermark_mspace(alloc, size, _error);
        if (!ret) {
            ZF_LOGI("Regular mspace alloc failed, and watermark also failed. for size %zu\n", size);
        }
        _end_operation(alloc, root_op);
        return ret;
    } else {
        _end_operation(alloc, root_op);
        SET_ERROR(_error, 1);
        return NULL;
    }
}

static int _allocman_cspace_alloc(allocman_t *alloc, cspacepath_t *slot, int use_watermark)
{
    int root_op;
    int error;
    /* see if we have an allocator installed yet*/
    if (!alloc->have_cspace) {
        return 1;
    }
    /* Check that we are permitted to cspace_alloc here */
    if (!_can_alloc(alloc->cspace.properties, alloc->cspace_alloc_depth, alloc->cspace_free_depth)) {
        if (use_watermark) {
            int ret = _try_watermark_cspace(alloc, slot);
            if (ret) {
                ZF_LOGI("Failed to allocate cslot from watermark\n");
            }
            return ret;
        } else {
            return 1;
        }
    }
    root_op = _start_operation(alloc);
    /* Attempt the allocation */
    alloc->cspace_alloc_depth++;
    error = alloc->cspace.alloc(alloc, alloc->cspace.cspace, slot);
    alloc->cspace_alloc_depth--;
    if (!error) {
        _end_operation(alloc, root_op);
        return 0;
    }
    /* We encountered some fail. We will try and allocate from the watermark pool.
       Does not matter what the error or outcome is, just propogate back up*/
    if (use_watermark) {
        error = _try_watermark_cspace(alloc, slot);
        if (error) {
            ZF_LOGI("Regular cspace alloc failed, and failed from watermark\n");
        }
        _end_operation(alloc, root_op);
        return error;
    } else {
        _end_operation(alloc, root_op);
        return 1;
    }
}

static seL4_Word _allocman_utspace_alloc(allocman_t *alloc, size_t size_bits, seL4_Word type, const cspacepath_t *path, uintptr_t paddr, bool canBeDev, int *_error, int use_watermark)
{
    int root_op;
    int error;
    seL4_Word ret;
    /* see if we have an allocator installed yet*/
    if (!alloc->have_utspace) {
        SET_ERROR(_error,1);
        return 0;
    }
    /* Check that we are permitted to utspace_alloc here */
    if (!_can_alloc(alloc->utspace.properties, alloc->utspace_alloc_depth, alloc->utspace_free_depth)) {
        if (use_watermark && paddr == ALLOCMAN_NO_PADDR) {
            ret = _try_watermark_utspace(alloc, size_bits, type, path, _error);
            if (ret == 0) {
                ZF_LOGI("Failed to allocate utspace from watermark. size %zu type %ld\n", size_bits, (long)type);
            }
            return ret;
        } else {
            SET_ERROR(_error, 1);
            return 0;
        }
    }
    root_op = _start_operation(alloc);
    /* Attempt the allocation */
    alloc->utspace_alloc_depth++;
    ret = alloc->utspace.alloc(alloc, alloc->utspace.utspace, size_bits, type, path, paddr, canBeDev, &error);
    alloc->utspace_alloc_depth--;
    if (!error) {
        _end_operation(alloc, root_op);
        SET_ERROR(_error, error);
        return ret;
    }
    /* We encountered some fail. We will try and allocate from the watermark pool.
       Does not matter what the error or outcome is, just propogate back up*/
    if (use_watermark && paddr == ALLOCMAN_NO_PADDR) {
        ret = _try_watermark_utspace(alloc, size_bits, type, path, _error);
        _end_operation(alloc, root_op);
        if (ret == 0) {
            ZF_LOGI("Regular utspace alloc failed and not watermark for size %zu type %ld\n", size_bits, (long)type);
        }
        return ret;
    } else {
        _end_operation(alloc, root_op);
        SET_ERROR(_error, 1);
        return 0;
    }
}

void *allocman_mspace_alloc(allocman_t *alloc, size_t size, int *_error)
{
    return _allocman_mspace_alloc(alloc, size, _error, 1);
}

int allocman_cspace_alloc(allocman_t *alloc, cspacepath_t *slot)
{
    return _allocman_cspace_alloc(alloc, slot, 1);
}

seL4_Word allocman_utspace_alloc_at(allocman_t *alloc, size_t size_bits, seL4_Word type, const cspacepath_t *path, uintptr_t paddr, bool canBeDev, int *_error)
{
    return _allocman_utspace_alloc(alloc, size_bits, type, path, paddr, canBeDev, _error, 1);
}

#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS /* CapBuddy support */

void vbt_tree_init(struct allocman *alloc, virtual_bitmap_tree_t *tree, uintptr_t paddr, seL4_CPtr origin, cspacepath_t dest_reg, size_t real_size);
void vbt_tree_query_blk(virtual_bitmap_tree_t *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr);
void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path);
void vbt_tree_list_insert(virtual_bitmap_tree_t **treeList, virtual_bitmap_tree_t *tree);
void vbt_tree_list_remove(virtual_bitmap_tree_t **treeList, virtual_bitmap_tree_t *tree);

static inline int vbt_tree_window_at_level(int target_layer, int index) {
    return 1ul << (target_layer - BITMAP_GET_LEVEL(index));
}

static uint64_t vbt_tree_sub_add_up(int index)
{
    uint64_t dtc = 0;
    int level = BITMAP_GET_LEVEL(index);
    for (int i = level + 1; i <= BITMAP_DEPTH; ++i) {
        for (int j = 0, r = 1ul<<(i-level); j < r; ++j) {
            dtc += VBT_INDEX_BIT(index * r + j);
        }
    }
    return dtc;
}

void vbt_tree_init(struct allocman *alloc, virtual_bitmap_tree_t *tree, uintptr_t paddr,
                   seL4_CPtr origin, cspacepath_t dest_reg, size_t real_size)
{
    tree->paddr = paddr;
    tree->entry.toplevel = 0;
    tree->entry.sublevel = 0;
    cspacepath_t origin_path = allocman_cspace_make_path(alloc, origin);
    tree->origin.capPtr = origin_path.capPtr;
    tree->origin.capDepth = origin_path.capDepth;
    tree->origin.dest = origin_path.dest;
    tree->origin.destDepth = origin_path.destDepth;
    tree->origin.offset = origin_path.offset;
    tree->origin.root = origin_path.root;
    tree->origin.window = origin_path.window;
    tree->pool_range.capPtr = dest_reg.capPtr;
    tree->pool_range.capDepth = dest_reg.capDepth;
    tree->pool_range.dest = dest_reg.dest;
    tree->pool_range.destDepth = dest_reg.destDepth;
    tree->pool_range.offset = dest_reg.offset;
    tree->pool_range.root = dest_reg.root;
    tree->pool_range.window = dest_reg.window;
    tree->blk_max_size = real_size;
    tree->blk_cur_size = real_size;
    tree->next = NULL;
    tree->prev = NULL;
    tree->top_tree.tnode[0] = 0ul;
    for (size_t i = 0; i < 32; ++i) {
        tree->sub_trees[i].tnode[0] = 0ul;
    }
    size_t size_bits = real_size - VBT_PAGE_GRAIN;
    assert(size_bits && size_bits <= 10);
    if (size_bits < BITMAP_LEVEL) {
        tree->entry.toplevel = 32;
        tree->entry.sublevel = VBT_SUBLEVEL_INDEX(size_bits);
        tree->top_tree.tnode[0] |= VBT_INDEX_BIT(32);
        tree->sub_trees[0].tnode[0] |= VBT_INDEX_BIT(tree->entry.sublevel);
        tree->sub_trees[0].tnode[0] |= vbt_tree_sub_add_up(tree->entry.sublevel);
    } else {
        tree->entry.toplevel = VBT_TOPLEVEL_INDEX(size_bits);
        tree->top_tree.tnode[0] |= VBT_INDEX_BIT(tree->entry.toplevel);
        tree->top_tree.tnode[0] |= vbt_tree_sub_add_up(tree->entry.toplevel);
        int window = vbt_tree_window_at_level(BITMAP_DEPTH, tree->entry.toplevel);
        int idx = BITMAP_SUB_OFFSET(window * tree->entry.toplevel);
        for (int i = idx; i < idx + window; ++i) {
            if (VBT_AND(tree->top_tree.tnode[0], VBT_INDEX_BIT(i))) {
                tree->sub_trees[i].tnode[0] = (uint64_t)-1;
                tree->sub_trees[i].tnode[0] &= MASK(63);
            }
        }
    }
}

void vbt_tree_query_blk(virtual_bitmap_tree_t *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr)
{
    res->sublevel = 0;
    res->toplevel = 0;
    struct vbt_bitmap *subl = NULL;
    struct vbt_bitmap *topl = &tree->top_tree;
    size_t size_bits = real_size - VBT_PAGE_GRAIN;
    size_t blk_size = BIT(real_size);
    bool query_level = size_bits > BITMAP_LEVEL;

    assert(size_bits <= 11 && size_bits >= 0);

    if (paddr != ALLOCMAN_NO_PADDR) {
        int idx = 0;
        if (query_level) {
            for (uintptr_t i = tree->paddr; paddr > i + blk_size; i += blk_size, ++idx);
            idx += VBT_TOPLEVEL_INDEX(size_bits);
            uint64_t dtc = VBT_INDEX_BIT(idx);
            if ((tree->top_tree.tnode[0] & dtc) == dtc) {
                res->toplevel = idx;
            }
        } else {
            uintptr_t i;
            size_t topl_blk_size = BIT(VBT_PAGE_GRAIN + BITMAP_LEVEL);
            for (i = tree->paddr; paddr > i + topl_blk_size; i += topl_blk_size, ++idx);
            idx += VBT_TOPLEVEL_INDEX(topl_blk_size);
            uint64_t dtc = VBT_INDEX_BIT(idx);
            if ((tree->top_tree.tnode[0] & dtc) == dtc) {
                res->toplevel = idx;
            }
            int stree_idx = idx;
            i = tree->paddr + i * topl_blk_size;
            for (idx = 0; paddr > i + blk_size; i += blk_size, ++idx);
            dtc = VBT_INDEX_BIT(idx);
            if ((tree->sub_trees[stree_idx].tnode[0] & dtc) == dtc) {
                res->sublevel = idx;
            }
        }
        return;
    }

    if (query_level) {
        int base = VBT_TOPLEVEL_INDEX(size_bits);
        int avail = CLZL(MASK((BITMAP_SIZE) - base) & (topl->tnode[0]));
        if (avail < base * 2) {
            res->toplevel = avail;
        }
    } else {
        for (int i = 32; i < 64 && !(res->sublevel); ++i) {
            if (VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                subl = &tree->sub_trees[BITMAP_SUB_OFFSET(i)];
                int base = VBT_SUBLEVEL_INDEX(size_bits);
                int avail = CLZL(MASK((BITMAP_SIZE) - base) & (subl->tnode[0]));
                if (avail < base * 2) {
                    res->toplevel = i;
                    res->sublevel = avail;
                }
            }
        }
    }
}

seL4_CPtr vbt_tree_acq_cap_idx(virtual_bitmap_tree_t *tree, const vbtspacepath_t *path)
{
    if (path->sublevel == 0) {
        int lv_size = BITMAP_DEPTH - BITMAP_GET_LEVEL(path->toplevel) + BITMAP_LEVEL;
        int lv_base = BIT(BITMAP_GET_LEVEL(path->toplevel)-1);
        int lv_offs = path->toplevel - lv_base;
        return lv_offs * BIT(lv_size);
    } else {
        int lv_size = BITMAP_DEPTH - BITMAP_GET_LEVEL(path->sublevel);
        int lv_base = BIT(BITMAP_GET_LEVEL(path->sublevel)-1);
        int lv_offs = path->sublevel - lv_base;
        return lv_offs * BIT(lv_size) + (path->toplevel - 32) * 32;
    }
}

void vbt_tree_restore_blk_from_bitmap(void *_bitmap, int index) {
    struct vbt_bitmap *bitmap = (struct vbt_bitmap*)_bitmap;

    bitmap->tnode[0] |= vbt_tree_sub_add_up(index);
    bitmap->tnode[0] |= VBT_INDEX_BIT(index);
    
    int buddy = index % 2 ? index - 1 : index + 1;
    if (!VBT_AND(bitmap->tnode[0], VBT_INDEX_BIT(buddy))) {
        return;
    }

    int idx = index >> 1;
    uint64_t dtc = VBT_INDEX_BIT(idx);
    while(idx) {
        bitmap->tnode[0] |= dtc;
        buddy = idx % 2 ? idx - 1 : idx + 1;
        if (!VBT_AND(bitmap->tnode[0], VBT_INDEX_BIT(buddy))) {
            return;
        }
        idx >>= 1;
        if (idx == 0) break;
        dtc = VBT_INDEX_BIT(idx);
    }
}

void vbt_tree_release_blk_from_bitmap(void *_bitmap, int index) {
    struct vbt_bitmap *bitmap = (struct vbt_bitmap*)_bitmap;
    int idx = index >> 1;
    uint64_t dtc = VBT_INDEX_BIT(idx);
    while(idx) {
        if (!VBT_AND(dtc, bitmap->tnode[0])) {
            break;
        }
        bitmap->tnode[0] -= dtc;
        idx >>= 1;
        dtc = VBT_INDEX_BIT(idx);
    }
    bitmap->tnode[0] &= ~vbt_tree_sub_add_up(index);
    bitmap->tnode[0] &= ~(VBT_INDEX_BIT(index));
}

void vbt_tree_update_avail_size(virtual_bitmap_tree_t *tree)
{
    struct vbt_bitmap *topl = &tree->top_tree;
    struct vbt_bitmap *subl = NULL;
    int t, utmost = 64;
    int blk_cur_idx = CLZL(topl->tnode[0]);
    if (blk_cur_idx >= 32) {
        for (int i = blk_cur_idx; i < 64; ++i) {
            if (VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                t = CLZL(MASK(63) & tree->sub_trees[BITMAP_SUB_OFFSET(i)].tnode[0]);
                if (t < utmost) {
                    utmost = t;
                }
            }
        }
        tree->blk_cur_size = (BITMAP_DEPTH) - BITMAP_GET_LEVEL(utmost) + (VBT_PAGE_GRAIN);
    } else {
        tree->blk_cur_size = ((BITMAP_DEPTH) - BITMAP_GET_LEVEL(blk_cur_idx)) + ((BITMAP_LEVEL) + (VBT_PAGE_GRAIN));
    }
    if (tree->blk_cur_size <= 12) {
        tree->blk_cur_size = 0;
    }
}

void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path) {
    virtual_bitmap_tree_t *tree = (virtual_bitmap_tree_t*)_tree;
    struct vbt_bitmap *topl = &tree->top_tree;
    struct vbt_bitmap *subl = NULL;

    if (!path->sublevel) {
        vbt_tree_release_blk_from_bitmap(topl, path->toplevel);
        int window = vbt_tree_window_at_level(BITMAP_DEPTH, path->toplevel);
        int sti = BITMAP_SUB_OFFSET(window * path->toplevel);
        for (int i = sti; i < sti + window; ++i) {
            if (!VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                tree->sub_trees[i].tnode[0] = 0ul;
            }
        }
    } else {
        subl = &tree->sub_trees[BITMAP_SUB_OFFSET(path->toplevel)];
        vbt_tree_release_blk_from_bitmap(subl, path->sublevel);
        int idx = path->toplevel;
        uint64_t dtc = VBT_INDEX_BIT(idx);
        while(idx) {
            if (!VBT_AND(dtc, topl->tnode[0])) {
                break;
            }
            topl->tnode[0] -= dtc;
            idx >>= 1;
            dtc = VBT_INDEX_BIT(idx);
        }
        if (subl->tnode[0] != 0) {
            topl->tnode[0] += (VBT_INDEX_BIT(path->toplevel));
        }
    }
    vbt_tree_update_avail_size(tree);
}

void vbt_tree_restore_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path) {
    virtual_bitmap_tree_t *tree = (virtual_bitmap_tree_t*)_tree;
    struct vbt_bitmap *topl = &tree->top_tree;
    struct vbt_bitmap *subl = NULL;

    if (!path->sublevel) {
        vbt_tree_restore_blk_from_bitmap(topl, path->toplevel);
        int window = vbt_tree_window_at_level(BITMAP_DEPTH, path->toplevel);
        int sti = BITMAP_SUB_OFFSET(window * path->toplevel);
        for (int i = sti; i < sti + window; ++i) {
            if (!VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                tree->sub_trees[i].tnode[0] = MASK(63) & (uint64_t)-1;
            }
        }
    } else {
        subl = &tree->sub_trees[BITMAP_SUB_OFFSET(path->toplevel)];
        vbt_tree_restore_blk_from_bitmap(subl, path->sublevel);
        int sublv_tree_index = path->toplevel;
        int buddy_tree_index = sublv_tree_index % 2 ? sublv_tree_index - 1 : sublv_tree_index + 1;
        if (subl->tnode[0] == MASK(63) &&
            subl->tnode[0] == tree->sub_trees[BITMAP_SUB_OFFSET(buddy_tree_index)].tnode[0]) {
            topl->tnode[0] |= (VBT_INDEX_BIT(sublv_tree_index));
            topl->tnode[0] |= (VBT_INDEX_BIT(buddy_tree_index));
            int buddy;
            int idx = path->toplevel >> 1;
            uint64_t dtc = VBT_INDEX_BIT(idx);
            while(idx) {
                topl->tnode[0] |= dtc;
                buddy = idx % 2 ? idx - 1 : idx + 1;
                if (!VBT_AND(topl->tnode[0], VBT_INDEX_BIT(buddy))) {
                    goto x;
                }
                idx >>= 1;
                if (idx == 0) break;
                dtc = VBT_INDEX_BIT(idx);
            }           
        }
    }
x:
    vbt_tree_update_avail_size(tree);
}

void vbt_tree_list_insert(virtual_bitmap_tree_t **treeList, virtual_bitmap_tree_t *tree)
{
    assert(tree);
    
    if (*treeList) {
        virtual_bitmap_tree_t *curr = *treeList;
        virtual_bitmap_tree_t *head = *treeList;
        for (; curr && curr->next && curr->next->pool_range.capPtr < tree->pool_range.capPtr; curr = curr->next);
        if (curr->pool_range.capPtr < tree->pool_range.capPtr) {
            tree->prev = curr;
            if (curr->next) {
                tree->next = curr->next;
                curr->next->prev = tree;
            }
            curr->next = tree;
        } else {
            assert(curr->pool_range.capPtr > tree->pool_range.capPtr);
            tree->next = curr;
            if (curr->prev) {
                tree->prev = curr->prev;
                curr->prev->next = tree;
            }
            curr->prev = tree;
            if (head->pool_range.capPtr > tree->pool_range.capPtr) {
                *treeList = tree;
            }
        }
    } else {
        if (tree->next) {
            tree->next->prev = tree->prev;
        }
        if (tree->prev) {
            tree->prev->next = tree->next;
        }
        tree->next = NULL;
        tree->prev = NULL;
        *treeList = tree;
    }
}

void tree_list_debug_print(virtual_bitmap_tree_t **treeList, virtual_bitmap_tree_t *empty) {
    for (int i = 0; i < 11; ++i) {
        printf("treelist[%d]: ", i);
        for (virtual_bitmap_tree_t *tree = treeList[i]; tree; tree = tree->next) {
            if (tree) {
                printf(" < capPtr: [%ld] ", tree->pool_range.capPtr);
                if (tree->prev) {
                    printf(" prev: {%ld} ", tree->prev->pool_range.capPtr);
                }
                if (tree->next) {
                    printf(" next: {%ld} ", tree->next->pool_range.capPtr);
                }
                printf("> ");
            }
        }
        printf("\n");
    }
    printf("\n [EmptyList] >>>> : \n");
    for (virtual_bitmap_tree_t *tree = empty; tree; tree = tree->next) {
        if (tree) {
            printf("   < capPtr: [%ld] ", tree->pool_range.capPtr);
            if (tree->prev) {
                printf(" prev: {%ld} ", tree->prev->pool_range.capPtr);
            }
            if (tree->next) {
                printf(" next: {%ld} ", tree->next->pool_range.capPtr);
            }
            printf("> \n");
        }
    }
    printf("\n");
}

void vbt_tree_list_remove(virtual_bitmap_tree_t **treeList, virtual_bitmap_tree_t *tree)
{
    assert(tree);
    assert(treeList);

    virtual_bitmap_tree_t *curr = *treeList;
    virtual_bitmap_tree_t *head = *treeList;

    for (; curr && curr != tree; curr = curr->next);

    assert(curr == tree);

    if (curr->prev != NULL) {
        curr->prev->next = curr->next;
    }
    if (curr->next != NULL) {
        curr->next->prev = curr->prev;
    }
    if (head == curr) {
        *treeList = curr->next;
    }
    curr->next = NULL;
    curr->prev = NULL;
    return;
}

void vbt_tree_debug_print(virtual_bitmap_tree_t *tree) {
    printf(">> cur-blk-size: %ld\n", tree->blk_cur_size);
    printf(">> pool_range: %ld\n", tree->pool_range.capPtr);
    printf("top-level: [%016lx]\n", tree->top_tree.tnode[0]);
    for (int i = 0; i < 32; ++i) {
        printf("sublv[%2d]: [%016lx] ", i, tree->sub_trees[i].tnode[0]);
        if ((i + 1) % 4 == 0 && i) {
            printf("\n");
        }
    }
}

int vbt_tree_acquire_multiple_frame_from_pool(struct vbt_forrest *pool, size_t real_size, seL4_CPtr *res)
{
    /* Make sure the arg 'real_size' of the requested memory region is legal */
    assert(real_size >= seL4_PageBits);

    /***
     * Try getting the first available virtual-bitmap-tree.
     * The tree must have no less than one piece of available memory region
     * that is large enough to meet the memory request (avail_size > real_size)
     */
    virtual_bitmap_tree_t *target_tree;

    size_t idx = /* memory pool is sorted by frame number (in bits) of the largest available memory region */
        real_size - seL4_PageBits;  /* 0, 1, 2, 4, ..., 256, 512, 1024 (2^0~10) frames */

    while (idx <= 10) {
        /***
         * As described above, 0 <= idx <= 10, and every unit in memory pool represents
         * a linked-list for the virtual-bitmap-trees with largest available memory region
         * of size 2^idx frames. Since no paddr is required, the query method is FCFS
         */
        target_tree = pool->mem_treeList[idx++];
        /***
         * NOTICE:
         *  It's feasible to query a tree with larger available
         *  memory region than the one we requested.
         */
        if (target_tree) {
            /* queried */
            break;
        }
    }
    /* align */
    idx -= 1;

    if (target_tree == NULL) {
        /* Failed to find available tree from CapBuddy's memory pool */
        ZF_LOGV("No available virtual-bitmap-tree has enough memory for %ld memory request", BIT(real_size));
        return -1;
    }

    /***
     * path to the available memory region in a virtual-bitmap-tree
     */
    vbtspacepath_t target_avail_mr;
    /***
     * Try getting the location of a available memory region from the target_tree.
     * A target_tree may have more than one available memory region to serve the
     * memory requested, so we need to find the first one.
     */

    vbt_tree_query_blk(
        target_tree,        // the first available virtual-bitmap-tree
        real_size,          // size (number of frames in bits) of requested memory region
        &target_avail_mr,   // destination variable (should then be initialized)
        ALLOCMAN_NO_PADDR   // FCFS means no particular physical address is required
    );

    vbt_tree_release_blk_from_vbt_tree(target_tree, &target_avail_mr);
    /***
     * Since 'res' denotes the first frame of the memory region to serve the request,
     * typically in capability-index form, we should calculate the cptr of the frame
     * and set it with the cptr.
     * NOTICE:
     *  [1][2][3][4] <- if we want [3], we should calculate it this way:
     * 
     *  base = cptr_of([1]), offset = 3 - 1, result = base + offset = cptr_of([1]) + 2
     * ------------------------------------------------------------------------------------
     * This works when we are in single level cspace, it should also be able to implemented
     * under other cspace structure. Another thing: frames (from Untyped_Retype) are linearly
     * distributing, so their capability index also construct a linear space (and it's fine
     * to be addressed by this convention: base + offset )
     * ------------------------------------------------------------------------------------
     */
    *res = target_tree->pool_range.capPtr + /* the first frame among the whole memory region managing by the tree */
            vbt_tree_acq_cap_idx(target_tree, &target_avail_mr); /* base + offset, so this is the offset */

    if (target_tree->blk_cur_size == (idx + seL4_PageBits)) {
        /***
         * Only happens when target_tree has more than 1 available
         * memory region to serve the memory request, which means
         * the updated tree status does not changed
         */
        return seL4_NoError;
    }
    
    /* Remove it from the original tree list of memory pool */
    vbt_tree_list_remove(&pool->mem_treeList[idx], target_tree);

    /***
     * If the updated virtual-bitmap-tree still has available memory region
     * to meet other memory requests, we need to add it back to the memory
     * pool, otherwise add it to the 'empty' list.
     */
    if (target_tree->blk_cur_size != 0) {
        /***
         * It the updated virtual-bitmap-tree has a different maximum available
         * memory region size, we need to insert it into a new tree linked-list.
         */
        idx = target_tree->blk_cur_size - seL4_PageBits;
        /* do the insertion */
        vbt_tree_list_insert(&pool->mem_treeList[idx], target_tree);
        return seL4_NoError;
    }

    virtual_bitmap_tree_t *tx = pool->empty;
    /* Add target tree into the empty list */
    if (tx) {
        /* FCFS */
        while (tx->next) {
            tx = tx->next;
        }
        tx->next = target_tree;
        /* Released from original list */
        if (target_tree->prev) {
            target_tree->prev->next = target_tree->next;
        }
        if (target_tree->next) {
            target_tree->next->prev = target_tree->prev;
        }
        /* (TAIL) Insert into empty list */
        target_tree->prev = tx;
        target_tree->next = NULL;
        return seL4_NoError;
    }
    /* Add it as the first one */
    pool->empty = target_tree;
    /* Released from original list */
    if (target_tree->next) {
        target_tree->next->prev = target_tree->prev;
    }
    if (target_tree->prev) {
        target_tree->prev->next = target_tree->next;
    }
    /* Initialization */
    target_tree->next = NULL;
    target_tree->prev = NULL;
    return seL4_NoError;
}

static int _allocman_cspace_csa(allocman_t *alloc, cspacepath_t *slots, size_t num_bits)
{
    int err = -1;
    /* Don't invoke it when nothing exists */
    if (!alloc->have_cspace) {
        return err;
    }
    int root_op = _start_operation(alloc);
    alloc->cspace_alloc_depth++;
    err = alloc->cspace.csa(alloc, alloc->cspace.cspace, slots, num_bits);
    alloc->cspace_alloc_depth--;
    _end_operation(alloc, root_op);
    return err;
}

/***
 *  This is just one wrapper function for the internal implementation
 *  of allocman's cspace_csa function '_allocman_cspace_csa(...)'
 * 
 * @note: csa = [c]ontiguous capability-[s]lots' pointers' [a]llocation
 * @param: alloc : the allocator to be invoked (allocman-allocator)
 * @param: slots : destination slots to fill in
 * @param: num_bits : how many capabilities slots you wish to mark as allocated
 */
int allocman_cspace_csa(allocman_t *alloc, cspacepath_t *slots, size_t num_bits)
{
    /* Call the internal function of allocman */
    return _allocman_cspace_csa(alloc, slots, num_bits);
}

static int _allocman_utspace_append_tcookie(allocman_t *alloc, virtual_bitmap_tree_t *tree)
{
    int error;

    tcookie_t *tck = allocman_mspace_alloc(alloc, sizeof(tcookie_t), &error);
    if (error) {
        return error;
    }
    tck->cptr = tree->pool_range.capPtr;
    tck->next = NULL;
    tck->prev = NULL;
    tck->tptr = tree;

    tcookie_t *curr = alloc->frame_pool.tcookieList;
    tcookie_t *head = alloc->frame_pool.tcookieList;

    if (!head) {
        alloc->frame_pool.tcookieList = tck;
        return 0;
    }

    for (; curr && curr->next && curr->next->cptr < tck->cptr; curr = curr->next);

    if (curr->cptr < tck->cptr) {
        tck->prev = curr;
        if (curr->next) {
            tck->next = curr->next;
            curr->next->prev = tck;
        }
        curr->next = tck;
    } else {
        assert(curr->cptr > tck->cptr);
        tck->next = curr;
        if (curr->prev) {
            tck->prev = curr->prev;
            curr->prev->next = tck;
        }
        curr->prev = tck;
        if (head->cptr > tck->cptr) {
            alloc->frame_pool.tcookieList = tck;
        }
    }
    return 0;
}

int allocman_utspace_try_alloc_from_pool(allocman_t *alloc, seL4_Word type, size_t size_bits,
                                         uintptr_t paddr, bool canBeDev, cspacepath_t *res)
{
    int err = -1;
    if (!alloc->have_utspace) {
        return err;
    }
    /***
     * It should be noted that the metadata of the target memory region
     * can be compressed. We can achieve this by returning 1 cspacepath
     * with its 'capPtr' set to the capability pointer of the first frame
     * of the requested memory region and its 'window' set to the number
     * of frames.
     * 
     *     frames: [1][2][3][4]
     *              ^
     *              |
     *            capPtr = 1 \
     *                        --> target cspacepath_t (compressed)
     *            window = 4 /
     * 
     * So in here, @param: frames_base_cptr = 1 (in the example)
     */
    seL4_CPtr frames_base_cptr;

    /***
     * Try acquiring frames for the requested memory region from CapBuddy,
     * if failed, we should try to construct one new virtual-bitmap tree
     * first, insert it into the memory pool (of CapBuddy), and we'll do
     * it again.
     * TODO:
     *  What it we failed at the second time? Should we try constructing
     *  new trees in an infinate loop? (I don't think that's proper and
     *  that can be the reason to rewrite the code)
     */
    err = vbt_tree_acquire_multiple_frame_from_pool(&alloc->frame_pool, size_bits, &frames_base_cptr);
    /* Failure occurred at our first approch */
    if (err != seL4_NoError) {
        /***
         * constant values to create a new virtual-bitmap-tree (configurable)
         */
        size_t frames_window_bits = 10; /* support 1024 now only */
        size_t frames_window_size = BIT(frames_window_bits);
        size_t memory_region_bits = frames_window_bits + seL4_PageBits;

        /* Allocated metadata before we truely allocating the capability */
        cspacepath_t untyped_original;
        /***
         * Try allocate cspace_path for the original untyped object so
         * as we can access to it under current cspace and move on.
         */
        err = allocman_cspace_alloc(alloc, &untyped_original);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to alloc slot for original untyped object.");
            return err;
        }

        /* Why cookies? -> retrieve physical address */
        /* cookie belongs to the internal allocator, we save it here. */
        seL4_CPtr untyped_original_cookie =
            allocman_utspace_alloc(alloc, memory_region_bits, seL4_UntypedObject,
                                                &untyped_original, canBeDev, &err);
        if (err != seL4_NoError) {
            /* return the bookkeeping value */
            allocman_cspace_free(alloc, &untyped_original);
            if (config_set(LIB_ALLOCMAN_DEBUG)) {
                ZF_LOGE("Failed to allocate original untyped object of size: %ld", BIT(memory_region_bits));
            }
            return err;
        }

        /***
         * Retrieve the physical address of the target memory region
         * (from the orginal untyped object's kernel information)
         */
        uintptr_t untyped_original_paddr =
            allocman_utspace_paddr(alloc, untyped_original_cookie, memory_region_bits);

        virtual_bitmap_tree_t *target_tree;
        /***
         * FIXME:
         *  What heap manager interface should be called here to store the virtual-bitmaps-
         *  tree's metadata? 'allocman_mspace_alloc' or 'malloc'->sel4muslibcsys? I think
         *  both of them are allocated from the '.bss' section during allocator's bootstrap.
         */
        target_tree = (virtual_bitmap_tree_t *)malloc(sizeof(virtual_bitmap_tree_t));
        if (!target_tree) {
            ZF_LOGE("Failed to allocate metadata to bookkeep vbt-tree information");
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            return err;
        }

        /***
         * @param: frame_cptr_sequence: records the compressed metadata of frames of the
         *         requested memory region (described at the entry of this function).
         */
        cspacepath_t frame_cptr_sequence;
        /*** 
         * @note: csa = [c]ontiguous capability-[s]lots' pointers' [a]llocation
         * 
         *  Here we try allocating metadata for the requested frames from the user-level
         *  cspace allocator, 'allocman_cspace_csa' is enabled when CapBuddy supports are
         *  enabled too.
         */
        err = allocman_cspace_csa(alloc, &frame_cptr_sequence, frames_window_bits);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to allocate contiguous slots for frames of the requested memory region");
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            free(target_tree);
            return err;
        }

        err =
            seL4_Untyped_Retype(
                untyped_original.capPtr,    /* '_service' : original untyped object cptr */
                seL4_ARCH_4KPage,           /* 'type' : target object type it retypes to */
                seL4_PageBits,              /* 'size' : target object size it retypes to */
                frame_cptr_sequence.root,       // [dest] -> cspace root to find the frame caps
                frame_cptr_sequence.dest,       // [dest] -> target cnode capability index (cptr)
                frame_cptr_sequence.destDepth,  // [dest] -> cnode depth to retrieve the cspace
                frame_cptr_sequence.offset,     // [dest] -> first frame capability index (cptr)
                frames_window_size          /* 'num_objects' : frame number from the requested memory region */
            );
        if (err != seL4_NoError) {
            /* Failed to retype to new frames through kernel interface from libsel4 */
            ZF_LOGE("Failed to invoke 'seL4_Untyped_Retype' to create frames for CapBuddy memory pool");
        /***
         * FIXME:
         *  Will we truely get here? Typically when every resource that needed are provided...
         */
            assert(0);
            /* return err; */
        }

        /***
         * When every thing is ready, let's put the newly created virtual-bitmap-tree into
         * CapBuddy's memory pool, and of course, we need to initialize a metadata for it.
         */
        vbt_tree_init(alloc, target_tree, untyped_original_paddr, untyped_original.capPtr, frame_cptr_sequence, memory_region_bits);

        /***
         * Insert the newly created virtual-bitmap-tree into the memory pool.
         * NOTICE:
         *  'frames_window_bits' here is to denote the size of requested memory region that
         *  a virtual-bitmap-tree is managing, which means by using 'frames_window_bits' are
         *  we able to place the tree correctly into the memory pool as there are a lot of
         *  virtual-bitmap-trees with different size in pool at the same time (this is because
         *  freeing and allocating method will affect the number of available frames in a tree
         *  so as to affect the available size of the tree, and the array passed here is sorted
         *  by the available memory size in the tree)
         */
        vbt_tree_list_insert(&alloc->frame_pool.mem_treeList[frames_window_bits], target_tree);

        /***
         * Rather than the virtual-bitmap-tree itself, we need to store its metdata for allocman
         * (the allocator) to do bookkeeping jobs and managing all available & unavailable trees.
         */
        err = _allocman_utspace_append_tcookie(alloc, target_tree);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to append newly created virtual-bitmap-tree to allocator");
            return err;
        }

        /* Now, retry acquiring frames from memory pool */
        err = vbt_tree_acquire_multiple_frame_from_pool(&alloc->frame_pool, size_bits, &frames_base_cptr);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to acquire frames from the newly created virtual-bitmap-tree, abort from CapBuddy");
            /***
             * TODO:
             *   Maybe we should return all of the resources allocated here to the allocator.
             */
            err = seL4_CNode_Revoke(untyped_original.dest, untyped_original.capPtr, untyped_original.capDepth);
            if (err != seL4_NoError) {
                ZF_LOGE("Failed to revoke the original untyped object's cap to delete all frames' capabilities");
                /* Will we get here? */
                assert(0);
            }
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            free(target_tree);
            /***
             * FIXME:
             *  allocator bookkeeping metadata for the target_tree needs to be free'd too,
             *  we need to implement this in the future...
             */
            while (true);   /* for debugging purpose, we should turn this on now */
            return err;
        }
    }
    /***
     * Initialize the return value by creating the compressed metadata
     * for frames of the requested memory region.
     */
    *res = allocman_cspace_make_path(alloc, frames_base_cptr);
    if (size_bits != seL4_PageBits) {
        /***
         * @param: size_bits : size in bits of the requested memory region
         * NOTICE:
         *  This's not the size of the memory region managing by the newly
         *  (if any exists) created virtual-bitmap-tree.
         */
        res->window = BIT(size_bits - seL4_PageBits);
    }
    return 0;
}

void allocman_utspace_try_free_from_pool(allocman_t *alloc, seL4_CPtr cptr)
{
    assert(alloc->frame_pool.tcookieList);
    
    tcookie_t *tck = alloc->frame_pool.tcookieList;
    
    for (; tck && cptr > (tck->cptr + 1023); tck = tck->next);

    assert(cptr >= tck->cptr);
    assert(cptr < tck->cptr + 1024);

    virtual_bitmap_tree_t *target = tck->tptr;
    size_t blk_cur_size = target->blk_cur_size;
    size_t global = cptr - target->pool_range.capPtr;
    vbtspacepath_t blk = {
        32 + global / 32,
        32 + global % 32
    };

    vbt_tree_restore_blk_from_vbt_tree(target, &blk);

    if (blk_cur_size != target->blk_cur_size) {
        assert(blk_cur_size < target->blk_cur_size);
        assert(blk_cur_size <= 22);
        if (blk_cur_size) {
            vbt_tree_list_remove(&alloc->frame_pool.mem_treeList[blk_cur_size - 12], target);
        } else {
            virtual_bitmap_tree_t *scanner = alloc->frame_pool.empty;
            for (; scanner->next && scanner != target; scanner = scanner->next);
            if (scanner == target) {
                if (scanner->prev) {
                    scanner->prev->next = scanner->next;
                }
                if (scanner->next) {
                    scanner->next->prev = scanner->prev;
                }
                if (target == alloc->frame_pool.empty) {
                    alloc->frame_pool.empty = target->next;
                }
                scanner->next = NULL;
                scanner->prev = NULL;
            } else {
                ZF_LOGE("Internal allocman error: unmatched tree pointer");
                assert(0);
            }
        }
        vbt_tree_list_insert(&alloc->frame_pool.mem_treeList[target->blk_cur_size - 12], target);
    }
}

int allocman_cspace_is_from_pool(allocman_t *alloc, seL4_CPtr cptr)
{
    int res;
    assert(alloc->have_cspace);
    int root = _start_operation(alloc);
    alloc->cspace_free_depth++;
    res = alloc->cspace.pool(alloc, alloc->cspace.cspace, cptr);
    alloc->cspace_free_depth--;
    _end_operation(alloc, root);
    return res;
}

#endif /* CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS */

static int _refill_watermark(allocman_t *alloc)
{
    int found_empty_pool;
    int did_allocation;
    size_t i;
    if (alloc->refilling_watermark || !alloc->used_watermark) {
        return 0;
    }
    alloc->refilling_watermark = 1;

    /* Run in a loop refilling our resources. We need a loop as refilling
       one resource may require another watermark resource to be used. It is up
       to the allocators to prove that this process results in a consistent
       increase in the watermark pool, and hence will terminate. Need to be
       very careful with re-entry in this loop, as our watermark resources
       may change anytime we perform an allocation. We try and allocate evenly
       across all the resources types since typically we are only refilling
       a single object from each resource anyway, so the performance will be
       the same, and if we aren't we are boot strapping and I'm not convinced
       that all allocations orders are equivalent in this case */
    int limit = 0;
    do {
        found_empty_pool = 0;
        did_allocation = 0;
        while (alloc->num_freed_slots > 0) {
            cspacepath_t slot = alloc->freed_slots[--alloc->num_freed_slots];
            allocman_cspace_free(alloc, &slot);
            /* a free is like an allocation in that we have made some progress */
            did_allocation = 1;
        }
        while (alloc->num_freed_mspace_chunks > 0) {
            struct allocman_freed_mspace_chunk chunk = alloc->freed_mspace_chunks[--alloc->num_freed_mspace_chunks];
            allocman_mspace_free(alloc, chunk.ptr, chunk.size);
            did_allocation = 1;
        }
        while (alloc->num_freed_utspace_chunks > 0) {
            struct allocman_freed_utspace_chunk chunk = alloc->freed_utspace_chunks[--alloc->num_freed_utspace_chunks];
            allocman_utspace_free(alloc, chunk.cookie, chunk.size_bits);
            did_allocation = 1;
        }
        if (alloc->num_cspace_slots < alloc->desired_cspace_slots) {
            int error;
            found_empty_pool = 1;
            cspacepath_t slot;
            error = _allocman_cspace_alloc(alloc, &slot, 0);
            if (!error) {
                alloc->cspace_slots[alloc->num_cspace_slots++] = slot;
                did_allocation = 1;
            }
        }
        for (i = 0; i < alloc->num_utspace_chunks; i++) {
            if (alloc->utspace_chunk_count[i] < alloc->utspace_chunk[i].count) {
                cspacepath_t slot;
                seL4_Word cookie;
                int error;
                /* First grab a slot */
                found_empty_pool = 1;
                error = allocman_cspace_alloc(alloc, &slot);
                if (!error) {
                    /* Now try to allocate */
                    cookie = _allocman_utspace_alloc(alloc, alloc->utspace_chunk[i].size_bits, alloc->utspace_chunk[i].type, &slot, ALLOCMAN_NO_PADDR, false, &error, 0);
                    if (!error) {
                        alloc->utspace_chunks[i][alloc->utspace_chunk_count[i]].cookie = cookie;
                        alloc->utspace_chunks[i][alloc->utspace_chunk_count[i]].slot = slot;
                        alloc->utspace_chunk_count[i]++;
                        did_allocation = 1;
                    } else {
                        /* Give the slot back */
                        allocman_cspace_free(alloc, &slot);
                    }
                }
            }
        }
        for (i = 0 ; i < alloc->num_mspace_chunks; i++) {
            if (alloc->mspace_chunk_count[i] < alloc->mspace_chunk[i].count) {
                void *result;
                int error;
                found_empty_pool = 1;
                result = _allocman_mspace_alloc(alloc, alloc->mspace_chunk[i].size, &error, 0);
                if (!error) {
                    alloc->mspace_chunks[i][alloc->mspace_chunk_count[i]++] = result;
                    did_allocation = 1;
                }
            }
        }
        limit++;
    } while (found_empty_pool && did_allocation && limit < 4);

    alloc->refilling_watermark = 0;
    if (!found_empty_pool) {
        alloc->used_watermark = 0;
    }
    return found_empty_pool;
}

int allocman_create(allocman_t *alloc, struct mspace_interface mspace) {
    /* zero out the struct */
    memset(alloc, 0, sizeof(allocman_t));

    alloc->mspace = mspace;
    alloc->have_mspace = 1;

    return 0;
}

int allocman_fill_reserves(allocman_t *alloc) {
    int full;
    int root = _start_operation(alloc);
    /* force the reserves to be checked */
    alloc->used_watermark = 1;
    /* attempt to fill */
    full = _refill_watermark(alloc);
    _end_operation(alloc, root);
    return full;
}

#define ALLOCMAN_ATTACH(alloc, space, interface) do { \
    int root = _start_operation(alloc); \
    assert(root); \
    if (alloc->have_##space) { \
        /* an untyped allocator has already been attached, bail */ \
        LOG_ERROR("Alocate of type " #space " is already attached"); \
        return 1; \
    } \
    alloc->space = interface; \
    alloc->have_##space = 1; \
    _end_operation(alloc, root); \
    return 0; \
}while(0)

int allocman_attach_utspace(allocman_t *alloc, struct utspace_interface utspace) {
    ALLOCMAN_ATTACH(alloc, utspace, utspace);
}

int allocman_attach_cspace(allocman_t *alloc, struct cspace_interface cspace) {
    ALLOCMAN_ATTACH(alloc, cspace, cspace);
}

static int resize_array(allocman_t *alloc, size_t num, void **array, size_t *size, size_t *count, size_t item_size) {
    int root = _start_operation(alloc);
    void *new_array;
    int error;

    assert(root);

    /* allocate new array */
    new_array = allocman_mspace_alloc(alloc, item_size * num, &error);
    if (!!error) {
        return error;
    }

    /* if we have less than before. throw an error */
    while (num < (*count)) {
        return -1;
    }

    /* copy any existing slots and free the old array, but avoid using a null array */
    if ((*array)) {
        memcpy(new_array, (*array), item_size * (*count));
        allocman_mspace_free(alloc, (*array), item_size * (*size));
    }

    /* switch the new array in */
    (*array) = new_array;
    (*size) = num;

    alloc->used_watermark = 1;
    _end_operation(alloc, root);
    return error;
}

static int resize_slots_array(allocman_t *alloc, size_t num, cspacepath_t **slots, size_t *size, size_t *count) {
    return resize_array(alloc, num, (void**)slots, size, count, sizeof(cspacepath_t));
}

int allocman_configure_cspace_reserve(allocman_t *alloc, size_t num) {
    return resize_slots_array(alloc, num, &alloc->cspace_slots, &alloc->desired_cspace_slots, &alloc->num_cspace_slots);
}

int allocman_configure_max_freed_slots(allocman_t *alloc, size_t num) {
    return resize_slots_array(alloc, num, &alloc->freed_slots, &alloc->desired_freed_slots, &alloc->num_freed_slots);
}

int  allocman_configure_max_freed_memory_chunks(allocman_t *alloc, size_t num) {
    return resize_array(alloc, num, (void**)&alloc->freed_mspace_chunks, &alloc->desired_freed_mspace_chunks, &alloc->num_freed_mspace_chunks, sizeof(struct allocman_freed_mspace_chunk));
}

int  allocman_configure_max_freed_untyped_chunks(allocman_t *alloc, size_t num) {
    return resize_array(alloc, num, (void**)&alloc->freed_utspace_chunks, &alloc->desired_freed_utspace_chunks, &alloc->num_freed_utspace_chunks, sizeof(struct allocman_freed_utspace_chunk));
}

int allocman_configure_utspace_reserve(allocman_t *alloc, struct allocman_utspace_chunk chunk) {
    int root = _start_operation(alloc);
    size_t i;
    struct allocman_utspace_chunk *new_chunk;
    size_t *new_counts;
    struct allocman_utspace_allocation **new_chunks;
    struct allocman_utspace_allocation *new_alloc;
    int error;
    /* ensure this chunk hasn't already been added. would be nice to handle both decreasing and
     * icnreasing reservations, but I cannot see the use case for that */
    for (i = 0; i < alloc->num_utspace_chunks; i++) {
        if (alloc->utspace_chunk[i].size_bits == chunk.size_bits && alloc->utspace_chunk[i].type == chunk.type) {
            return 1;
        }
    }
    /* tack this chunk on */
    new_chunk = allocman_mspace_alloc(alloc, sizeof(struct allocman_utspace_chunk) * (alloc->num_utspace_chunks + 1), &error);
    if (error) {
        return error;
    }
    new_counts = allocman_mspace_alloc(alloc, sizeof(size_t) * (alloc->num_utspace_chunks + 1), &error);
    if (error) {
        allocman_mspace_free(alloc, new_chunk, sizeof(struct allocman_utspace_chunk) * (alloc->num_utspace_chunks + 1));
        return error;
    }
    new_chunks = allocman_mspace_alloc(alloc, sizeof(struct allocman_utspace_allocation *) * (alloc->num_utspace_chunks + 1), &error);
    if (error) {
        allocman_mspace_free(alloc, new_chunk, sizeof(struct allocman_utspace_chunk) * (alloc->num_utspace_chunks + 1));
        allocman_mspace_free(alloc, new_counts, sizeof(size_t) * (alloc->num_utspace_chunks + 1));
        return error;
    }
    new_alloc = allocman_mspace_alloc(alloc, sizeof(struct allocman_utspace_allocation) * chunk.count, &error);
    if (error) {
        allocman_mspace_free(alloc, new_chunk, sizeof(struct allocman_utspace_chunk) * (alloc->num_utspace_chunks + 1));
        allocman_mspace_free(alloc, new_counts, sizeof(size_t) * (alloc->num_utspace_chunks + 1));
        allocman_mspace_free(alloc, new_chunks, sizeof(struct allocman_utspace_allocation *) * (alloc->num_utspace_chunks + 1));
        return error;
    }
    if (alloc->num_utspace_chunks > 0) {
        memcpy(new_chunk, alloc->utspace_chunk, sizeof(struct allocman_utspace_chunk) * alloc->num_utspace_chunks);
        memcpy(new_counts, alloc->utspace_chunk_count, sizeof(size_t) * alloc->num_utspace_chunks);
        memcpy(new_chunks, alloc->utspace_chunks, sizeof(struct allocman_utspace_allocation *) * alloc->num_utspace_chunks);
        allocman_mspace_free(alloc, alloc->utspace_chunk, sizeof(struct allocman_utspace_chunk) * alloc->num_utspace_chunks);
        allocman_mspace_free(alloc, alloc->utspace_chunk_count, sizeof(size_t) * alloc->num_utspace_chunks);
        allocman_mspace_free(alloc, alloc->utspace_chunks, sizeof(struct allocman_utspace_allocation *) * alloc->num_utspace_chunks);
    }
    new_chunk[alloc->num_utspace_chunks] = chunk;
    new_counts[alloc->num_utspace_chunks] = 0;
    new_chunks[alloc->num_utspace_chunks] = new_alloc;
    alloc->utspace_chunk = new_chunk;
    alloc->utspace_chunk_count = new_counts;
    alloc->utspace_chunks = new_chunks;
    alloc->num_utspace_chunks++;
    alloc->used_watermark = 1;
    _end_operation(alloc, root);
    return 0;
}

int allocman_configure_mspace_reserve(allocman_t *alloc, struct allocman_mspace_chunk chunk) {
    int root = _start_operation(alloc);
    size_t i;
    struct allocman_mspace_chunk *new_chunk;
    size_t *new_counts;
    void ***new_chunks;
    void **new_alloc;
    int error;
    /* ensure this chunk hasn't already been added. would be nice to handle both decreasing and
     * icnreasing reservations, but I cannot see the use case for that */
    for (i = 0; i < alloc->num_mspace_chunks; i++) {
        if (alloc->mspace_chunk[i].size == chunk.size) {
            return 1;
        }
    }
    /* tack this chunk on */
    new_chunk = allocman_mspace_alloc(alloc, sizeof(struct allocman_mspace_chunk) * (alloc->num_mspace_chunks + 1), &error);
    if (error) {
        return error;
    }
    new_counts = allocman_mspace_alloc(alloc, sizeof(size_t) * (alloc->num_mspace_chunks + 1), &error);
    if (error) {
        allocman_mspace_free(alloc, new_chunk, sizeof(struct allocman_mspace_chunk) * (alloc->num_mspace_chunks + 1));
        return error;
    }
    new_chunks = allocman_mspace_alloc(alloc, sizeof(void **) * (alloc->num_mspace_chunks + 1), &error);
    if (error) {
        allocman_mspace_free(alloc, new_chunk, sizeof(struct allocman_mspace_chunk) * (alloc->num_mspace_chunks + 1));
        allocman_mspace_free(alloc, new_counts, sizeof(size_t) * (alloc->num_mspace_chunks + 1));
        return error;
    }
    new_alloc = allocman_mspace_alloc(alloc, sizeof(void *) * chunk.count, &error);
    if (error) {
        allocman_mspace_free(alloc, new_chunk, sizeof(struct allocman_mspace_chunk) * (alloc->num_mspace_chunks + 1));
        allocman_mspace_free(alloc, new_counts, sizeof(size_t) * (alloc->num_mspace_chunks + 1));
        allocman_mspace_free(alloc, new_chunks, sizeof(void **) * (alloc->num_mspace_chunks + 1));
        return error;
    }
    if (alloc->num_mspace_chunks > 0) {
        memcpy(new_chunk, alloc->mspace_chunk, sizeof(struct allocman_mspace_chunk) * alloc->num_mspace_chunks);
        memcpy(new_counts, alloc->mspace_chunk_count, sizeof(size_t) * alloc->num_mspace_chunks);
        memcpy(new_chunks, alloc->mspace_chunks, sizeof(void **) * alloc->num_mspace_chunks);
        allocman_mspace_free(alloc, alloc->mspace_chunk, sizeof(struct allocman_mspace_chunk) * alloc->num_mspace_chunks);
        allocman_mspace_free(alloc, alloc->mspace_chunk_count, sizeof(size_t) * alloc->num_mspace_chunks);
        allocman_mspace_free(alloc, alloc->mspace_chunks, sizeof(void **) * alloc->num_mspace_chunks);
    }
    new_chunk[alloc->num_mspace_chunks] = chunk;
    new_counts[alloc->num_mspace_chunks] = 0;
    new_chunks[alloc->num_mspace_chunks] = new_alloc;
    alloc->mspace_chunk = new_chunk;
    alloc->mspace_chunk_count = new_counts;
    alloc->mspace_chunks = new_chunks;
    alloc->num_mspace_chunks++;
    alloc->used_watermark = 1;
    _end_operation(alloc, root);
    return 0;
}


int allocman_add_untypeds_from_timer_objects(allocman_t *alloc, timer_objects_t *to) {
    int error = 0;
    for (size_t i = 0; i < to->nobjs; i++) {
        cspacepath_t path = allocman_cspace_make_path(alloc, to->objs[i].obj.cptr);
        error = allocman_utspace_add_uts(alloc, 1, &path, &to->objs[i].obj.size_bits,
                                        (uintptr_t *) &to->objs[i].region.base_addr,
                                        ALLOCMAN_UT_DEV);
        if (error) {
            ZF_LOGE("Failed to add ut to allocman");
            return error;
        }
    }
    return 0;
}

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

#ifdef CONFIG_LAMP

void vbt_tree_init(struct allocman *alloc, struct vbt_tree *tree, uintptr_t paddr, seL4_CPtr origin, cspacepath_t dest_reg, size_t real_size);
void vbt_tree_query_blk(struct vbt_tree *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr);
void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path);
void vbt_tree_list_insert(struct vbt_tree **treeList, struct vbt_tree *tree);
void vbt_tree_list_remove(struct vbt_tree **treeList, struct vbt_tree *tree);
int vbt_tree_acquire_frame_from_pool(struct vbt_forrest *pool, size_t real_size, seL4_CPtr *res);

static inline int vbt_tree_window_at_level(int target_layer, int index) {
    //if (index >= 32) {
    //    assert(0);
    //}
    return 1ul << (target_layer - BITMAP_GET_LEVEL(index));
}

static size_t vbt_tree_sub_add_up(int index)
{
    size_t dtc = 0;
    int level = BITMAP_GET_LEVEL(index);
    for (int i = level + 1; i <= BITMAP_DEPTH; ++i) {
        for (int j = 0, r = 1ul<<(i-level); j < r; ++j) {
            dtc += VBT_INDEX_BIT(index * r + j);
        }
    }
    return dtc;
}

void vbt_tree_init(struct allocman *alloc, struct vbt_tree *tree, uintptr_t paddr,
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
                tree->sub_trees[i].tnode[0] = (size_t)-1;
                tree->sub_trees[i].tnode[0] &= MASK(63);
            }
        }
    }
}

void vbt_tree_query_blk(struct vbt_tree *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr)
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
    /**
     * Is it necessary to cal all related value ?
     * Maybe the only thing that we should do is seeing if
     * the bit field value of blk in bitmap equals to TRUE or not...
     */
        int idx = 0;
        if (query_level) {
            for (uintptr_t i = tree->paddr; paddr > i + blk_size; i += blk_size, ++idx);
            idx += VBT_TOPLEVEL_INDEX(size_bits);
            size_t dtc = VBT_INDEX_BIT(idx);
            if ((tree->top_tree.tnode[0] & dtc) == dtc) {
                res->toplevel = idx;
            }
        } else {
            uintptr_t i;
            size_t topl_blk_size = BIT(VBT_PAGE_GRAIN + BITMAP_LEVEL);
            for (i = tree->paddr; paddr > i + topl_blk_size; i += topl_blk_size, ++idx);
            idx += VBT_TOPLEVEL_INDEX(topl_blk_size);
            size_t dtc = VBT_INDEX_BIT(idx);
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
            if (VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i)))
            {
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

seL4_CPtr vbt_tree_acq_cap_idx(struct vbt_tree *tree, const vbtspacepath_t *path)
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
    size_t dtc = VBT_INDEX_BIT(idx);
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
    size_t dtc = VBT_INDEX_BIT(idx);
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

void vbt_tree_update_avail_size(struct vbt_tree *tree)
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
    struct vbt_tree *tree = (struct vbt_tree*)_tree;
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
        size_t dtc = VBT_INDEX_BIT(idx);
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
    struct vbt_tree *tree = (struct vbt_tree*)_tree;
    struct vbt_bitmap *topl = &tree->top_tree;
    struct vbt_bitmap *subl = NULL;

    if (!path->sublevel) {
        vbt_tree_restore_blk_from_bitmap(topl, path->toplevel);
        int window = vbt_tree_window_at_level(BITMAP_DEPTH, path->toplevel);
        int sti = BITMAP_SUB_OFFSET(window * path->toplevel);
        for (int i = sti; i < sti + window; ++i) {
            if (!VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                tree->sub_trees[i].tnode[0] = MASK(63) & (size_t)-1;
            }
        }
    } else {
        subl = &tree->sub_trees[BITMAP_SUB_OFFSET(path->toplevel)];

        vbt_tree_restore_blk_from_bitmap(subl, path->sublevel);

        int sublv_tree_index = path->toplevel;
        int buddy_tree_index = sublv_tree_index % 2 ? sublv_tree_index - 1 : sublv_tree_index + 1;

        if (subl->tnode[0] == MASK(63) &&
            subl->tnode[0] == tree->sub_trees[BITMAP_SUB_OFFSET(buddy_tree_index)].tnode[0])
        {
            topl->tnode[0] |= (VBT_INDEX_BIT(sublv_tree_index));
            topl->tnode[0] |= (VBT_INDEX_BIT(buddy_tree_index));

            int buddy;
            int idx = path->toplevel >> 1;
            size_t dtc = VBT_INDEX_BIT(idx);
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

void vbt_tree_list_insert(struct vbt_tree **treeList, struct vbt_tree *tree)
{
    assert(tree);
    
    if (*treeList) {
        struct vbt_tree *curr = *treeList;
        struct vbt_tree *head = *treeList;
        for (; curr && curr->next && curr->next->paddr < tree->paddr; curr = curr->next);
        if (curr->paddr < tree->paddr) {
            tree->prev = curr;
            if (curr->next) {
                tree->next = curr->next;
                curr->next->prev = tree;
            }
            curr->next = tree;
        } else {
            assert(curr->paddr > tree->paddr);
            tree->next = curr;
            if (curr->prev) {
                tree->prev = curr->prev;
                curr->prev->next = tree;
            }
            curr->prev = tree;
            if (head->paddr > tree->paddr) {
                *treeList = tree;
            }
        }
    } else {
        *treeList = tree;
        if (tree->next) {
            tree->next->prev = tree->prev;
        }
        if (tree->prev) {
            tree->prev->next = tree->next;
        }
        tree->next = NULL;
        tree->prev = NULL;
    }
}

void tree_list_debug_print(struct vbt_tree **treeList, struct vbt_tree *empty) {
    for (int i = 0; i < 11; ++i) {
        printf("treelist[%d]: ", i);
        for (struct vbt_tree *tree = treeList[i]; tree; tree = tree->next) {
            if (tree) {
                //printf(" < vaddr: %016llx capPtr: [%ld] vaddr: %016llx ", &tree->pool_range,
                //                    tree->pool_range.capPtr, &tree->sub_trees[31]);
                printf(" < capPtr: [%ld] ", tree->pool_range.capPtr);
                if (tree->prev) {
                    printf(" prev: {%ld} ", tree->prev->pool_range.capPtr);
                }
                if (tree->next) {
                    printf(" next: {%ld} ", tree->next->pool_range.capPtr);
                }
                printf("> ");
                //tree_debug_print(tree);
            }
        }
        printf("\n");
    }
    printf("\n [EmptyList] >>>> : \n");
    for (struct vbt_tree *tree = empty; tree; tree = tree->next) {
        if (tree) {
            //printf(" < vaddr: %016llx capPtr: [%ld] vaddr: %016llx ", &tree->pool_range,
            //                        tree->pool_range.capPtr, &tree->sub_trees[31]);
            printf("   < capPtr: [%ld] ", tree->pool_range.capPtr);
            if (tree->prev) {
                printf(" prev: {%ld} ", tree->prev->pool_range.capPtr);
            }
            if (tree->next) {
                printf(" next: {%ld} ", tree->next->pool_range.capPtr);
            }
            printf("> \n");
            //printf(" [%ld] ", tree->pool_range.capPtr);
            //if (tree->pool_range.capPtr == 0) {
            //    vbt_tree_debug_print(tree);
            //}
        }
    }
    printf("\n");
}

void vbt_tree_list_remove(struct vbt_tree **treeList, struct vbt_tree *tree)
{
    assert(tree);
    assert(treeList);

    struct vbt_tree *curr = *treeList;
    struct vbt_tree *head = *treeList;

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

void vbt_tree_debug_print(struct vbt_tree *tree) {
    printf(">> cur-blk-size: %ld\n", tree->blk_cur_size);
    printf(">> pool_range: %ld\n", tree->pool_range.capPtr);
    printf("top-level: [%016llx]\n", tree->top_tree.tnode[0]);
    for (int i = 0; i < 32; ++i) {
        printf("sublv[%2d]: [%016llx] ", i, tree->sub_trees[i].tnode[0]);
        if ((i + 1) % 4 == 0 && i) {
            printf("\n");
        }
    }
}

int vbt_tree_acquire_multiple_frame_from_pool(struct vbt_forrest *pool, size_t real_size, seL4_CPtr *res)
{
    size_t size_bits = real_size - seL4_PageBits;
    assert(size_bits >= 0);
    int target_level = size_bits;
    struct vbt_tree *tree = pool->mem_treeList[target_level];
    for (int i = target_level + 1; !tree && i < 11; ++i) {
        tree = pool->mem_treeList[i];
    }
    struct vbt_tree *old = tree;
    if (!tree) {
        /* Unable to find avail tree currently */
        return 1;
    }

    size_t curr_blk_size = tree->blk_cur_size;
    vbtspacepath_t blk = {0, 0};
    
    vbt_tree_query_blk(tree, real_size, &blk, ALLOCMAN_NO_PADDR);
    *res = vbt_tree_acq_cap_idx(tree, &blk) + tree->pool_range.capPtr;    
    vbt_tree_release_blk_from_vbt_tree(tree, &blk);

    if (tree->blk_cur_size == curr_blk_size) {
        return 0;
    }
    vbt_tree_list_remove(&pool->mem_treeList[curr_blk_size - 12], tree);
    if (tree->blk_cur_size != 0) {
        vbt_tree_list_insert(&pool->mem_treeList[tree->blk_cur_size - 12], tree);
        return 0;
    }

    if (pool->empty) {
        struct vbt_tree *scanner = pool->empty;
        for (; scanner->next; scanner = scanner->next);
        if (tree->prev) {
            tree->prev->next = tree->next;
        }
        if (tree->next) {
            tree->next->prev = tree->prev;
        }
        scanner->next = tree;
        tree->prev = scanner;
        tree->next = NULL;
    } else {
        pool->empty = tree;
        if (tree->next) {
            tree->next->prev = tree->prev;
        }
        if (tree->prev) {
            tree->prev->next = tree->next;
        }
        tree->next = NULL;
        tree->prev = NULL;
    }
    return 0;
}

static int _allocman_cspace_csa(allocman_t *alloc, cspacepath_t *slots, size_t num_bits)
{
    int root_op;
    int error;

    if (!alloc->have_cspace) {
        return 1;
    }

    root_op = _start_operation(alloc);
    alloc->cspace_alloc_depth++;
    error = alloc->cspace.csa(alloc, alloc->cspace.cspace, slots, num_bits);
    alloc->cspace_alloc_depth--;
    _end_operation(alloc, root_op);
    return error;
}

int allocman_cspace_csa(allocman_t *alloc, cspacepath_t *slots, size_t num_bits)
{
    return _allocman_cspace_csa(alloc, slots, num_bits);
}

static int _allocman_utspace_append_tcookie(allocman_t *alloc, struct vbt_tree *tree)
{
    int error;

    tcookie_t *tck = allocman_mspace_alloc(alloc, sizeof(tcookie_t), &error);
    if (error) {
        //!
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
    int error;
    if (!alloc->have_utspace) {
        //ZF_LOGE("No utspace provided.");
        return 1;
    }

    seL4_CPtr slot;
    while (vbt_tree_acquire_multiple_frame_from_pool(&alloc->frame_pool, size_bits, &slot)) {

        struct vbt_tree *nt = NULL;
        cspacepath_t src_slot;
        cspacepath_t des_slot;
        seL4_CPtr cookie;
        uintptr_t paddr;

        error = allocman_cspace_alloc(alloc, &src_slot);
        if (error) {
            ZF_LOGE("Failed to alloc slot for origin untyped object.");
            return error;
        }

        cookie = allocman_utspace_alloc(alloc, 22, seL4_UntypedObject, &src_slot, false, &error);
        if (error) {
            //ZF_LOGE("Failed to create untyped object from utspace allocator.");
            allocman_cspace_free(alloc, &src_slot);
            return error;
        }
        paddr = allocman_utspace_paddr(alloc, cookie, 22);

        nt = (struct vbt_tree *)allocman_mspace_alloc(alloc, sizeof(struct vbt_tree), &error);
        if (error) {
            ZF_LOGE("Failed to alloc metadata to keep vbt-tree info.");
            allocman_cspace_free(alloc, &src_slot);
            allocman_utspace_free(alloc, cookie, 22);
            return error;
        }
        error = allocman_cspace_csa(alloc, &des_slot, 10);
        if (error) {
            ZF_LOGE("Failed to alloc contiguous slots for pre-allocated frames.");
            allocman_cspace_free(alloc, &src_slot);
            allocman_utspace_free(alloc, cookie, 22);
            allocman_mspace_free(alloc, nt, sizeof(*nt));
            return error;
        }

        vka_object_t origin = {src_slot.capPtr, cookie, seL4_UntypedObject, 22};
        error = vka_untyped_retype(&origin, seL4_ARCH_4KPage, 12, 1024, &des_slot);
        if (error) {
            ZF_LOGE("[ERROR]: FAILED TO RETYPE CONTIGUOUS 4K PAGES.");
            return error;
        }

        vbt_tree_init(alloc, nt, paddr, src_slot.capPtr, des_slot, 22);
        vbt_tree_list_insert(&alloc->frame_pool.mem_treeList[10], nt);

        error = _allocman_utspace_append_tcookie(alloc, nt);
        if (error) {
            //
            return error;
        }
    }

    *res = allocman_cspace_make_path(alloc, slot);
    if (size_bits != 12) {
        res->window = BIT(size_bits - 12);
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

    struct vbt_tree *target = tck->tptr;
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
            struct vbt_tree *scanner = alloc->frame_pool.empty;
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

#endif

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

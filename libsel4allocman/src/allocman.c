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

#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS

void vbt_tree_init(struct allocman *alloc, vbtree_t *tree, uintptr_t paddr, seL4_CPtr origin, cspacepath_t dest_reg, size_t real_size);
void vbt_tree_query_blk(vbtree_t *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr);
void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path);
void vbt_tree_list_insert(vbtree_t **treeList, vbtree_t *tree);
void vbt_tree_list_remove(vbtree_t **treeList, vbtree_t *tree);
int vbt_tree_acquire_frame_from_pool(struct vbt_forrest *pool, size_t real_size, seL4_CPtr *res);

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

void vbt_tree_init(struct allocman *alloc, vbtree_t *tree, uintptr_t paddr,
                   seL4_CPtr origin, cspacepath_t dest_reg, size_t real_size)
{
    tree->paddr = paddr;
    tree->frames_cptr_base = dest_reg.capPtr;
    tree->blk_cur_size = real_size;

    size_t size_bits = real_size - seL4_PageBits;

    if (size_bits < BITMAP_LEVEL) {
        tree->entry.toplevel = 32;
        tree->entry.sublevel = VBT_SUBLEVEL_INDEX(size_bits);
        tree->top_tree.tnode[0] |= VBT_INDEX_BIT(32);
        tree->sub_trees[0].tnode[0] |= VBT_INDEX_BIT(tree->entry.sublevel);
        tree->sub_trees[0].tnode[0] |= vbt_tree_sub_add_up(tree->entry.sublevel);
        return;
    }
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

void vbt_tree_query_blk(vbtree_t *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr)
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
        return;
    }

    size_t map_l1;
    size_t avail_index;

    map_l1 = topl->tnode[0];
    /* replace for loop with FFSL -> O(n) loop with O(logn) */
    while (!res->sublevel) {
        avail_index = 64 - FFSL(map_l1);
        subl = &tree->sub_trees[BITMAP_SUB_OFFSET(avail_index)];
        int base = VBT_SUBLEVEL_INDEX(size_bits);
        int avail = CLZL(MASK((BITMAP_SIZE) - base) & (subl->tnode[0]));
        if (avail < base * 2) {
            res->toplevel = avail_index;
            res->sublevel = avail;
        } else {
            map_l1 &= ~(1ULL << (FFSL(map_l1) - 1));
        }
    }
}

seL4_CPtr vbt_tree_acq_cap_idx(vbtree_t *tree, const vbtspacepath_t *path)
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
    while(idx) {
        bitmap->tnode[0] |= (1ULL << (BITMAP_SIZE - 1 - idx));
        buddy = idx % 2 ? idx - 1 : idx + 1;
        if (!((bitmap->tnode[0] >> (BITMAP_SIZE - 1 - buddy)) & 1)) {
            return;
        }
        idx >>= 1;
    }
}

void vbt_tree_release_blk_from_bitmap(void *_bitmap, int index) {
    struct vbt_bitmap *bitmap = (struct vbt_bitmap*)_bitmap;
    int idx = index >> 1;
    while(idx) {
        if (!((bitmap->tnode[0] >> (BITMAP_SIZE - 1 - idx)) & 1)) {
            break;
        }
        bitmap->tnode[0] &= ~(1ULL << (BITMAP_SIZE - 1 - idx));
        idx >>= 1;
    }
    bitmap->tnode[0] &= ~vbt_tree_sub_add_up(index);
    bitmap->tnode[0] &= ~(VBT_INDEX_BIT(index));
}

void vbt_tree_update_avail_size(vbtree_t *tree)
{
    struct vbt_bitmap *topl = &tree->top_tree;
    struct vbt_bitmap *subl = NULL;

    int t, utmost = 64;
    int blk_cur_idx = CLZL(topl->tnode[0]);
    if (blk_cur_idx >= 32) {
        /* top level bitmap */
        size_t map_l1 = topl->tnode[0];
        while (map_l1) {
            blk_cur_idx = 64 - FFSL(map_l1);
            if (blk_cur_idx < 32) break;
            t = CLZL(MASK(63) & tree->sub_trees[BITMAP_SUB_OFFSET(blk_cur_idx)].tnode[0]);
            utmost = t < utmost ? t: utmost;
            if (utmost == 1) break;
            map_l1 &= ~(1ULL << (FFSL(map_l1) - 1));
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
    vbtree_t *tree = (vbtree_t*)_tree;
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
        while(idx) {
            if (!((topl->tnode[0] >> (BITMAP_SIZE - 1 - idx)) & 1)) {
                break;
            }
            topl->tnode[0] &= ~(1ULL << (BITMAP_SIZE - 1 - idx));
            idx >>= 1;
        }
        if (subl->tnode[0] != 0) {
            topl->tnode[0] += (VBT_INDEX_BIT(path->toplevel));
        }
    }
    vbt_tree_update_avail_size(tree);
}

void vbt_tree_restore_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path) {
    vbtree_t *tree = (vbtree_t*)_tree;
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
        vbt_tree_update_avail_size(tree);
        return;
    }
    
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
        while(idx) {
            topl->tnode[0] |= (1ULL << (BITMAP_SIZE - 1 - idx));
            buddy = idx % 2 ? idx - 1 : idx + 1;
            if (!((topl->tnode[0] >> (BITMAP_SIZE - 1 - buddy)) & 1)) {
                break;
            }
            idx >>= 1;
        }           
    }
    vbt_tree_update_avail_size(tree);
}

void vbt_tree_list_insert(vbtree_t **treeList, vbtree_t *tree)
{
    assert(tree);

    if (*treeList) {
        vbtree_t *curr = *treeList;
        vbtree_t *head = *treeList;
        for (; curr && curr->next && curr->next->frames_cptr_base < tree->frames_cptr_base; curr = curr->next);
        if (curr->frames_cptr_base < tree->frames_cptr_base) {
            tree->prev = curr;
            if (curr->next) {
                tree->next = curr->next;
                curr->next->prev = tree;
            }
            curr->next = tree;
        } else {
            assert(curr->frames_cptr_base > tree->frames_cptr_base);
            tree->next = curr;
            if (curr->prev) {
                tree->prev = curr->prev;
                curr->prev->next = tree;
            }
            curr->prev = tree;
            if (head->frames_cptr_base > tree->frames_cptr_base) {
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

void vbt_tree_list_remove(vbtree_t **treeList, vbtree_t *tree)
{
    assert(tree);
    assert(treeList);

    vbtree_t *curr = *treeList;
    vbtree_t *head = *treeList;

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

static vbtree_t *capbuddy_query_avail_vbt(struct vbt_forrest *pool, size_t real_size)
{
    size_t size_bits = real_size - seL4_PageBits;
    vbtree_t *tree = pool->mem_treeList[size_bits];
    for (size_t i = size_bits + 1; !tree && i < 11; ++i) {
        tree = pool->mem_treeList[i];
    }
    return tree;
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

static int _allocman_utspace_append_tcookie(allocman_t *alloc, vbtree_t *tree)
{
    int error;

    tcookie_t *tck = allocman_mspace_alloc(alloc, sizeof(tcookie_t), &error);
    if (error) {
        return error;
    }
    tck->cptr = tree->frames_cptr_base;
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
        return 1;
    }
    /* dest slot for the starting cptr */
    seL4_CPtr slot;

    vbtree_t *ptr_tree;
    ptr_tree = capbuddy_query_avail_vbt(&alloc->frame_pool, size_bits);

    if (!ptr_tree) {
        cspacepath_t src_slot;
        cspacepath_t des_slot;
        seL4_CPtr cookie;
        uintptr_t paddr;

        error = allocman_cspace_alloc(alloc, &src_slot);
        if (error) {
            ZF_LOGE("Failed to alloc slot for origin untyped object.");
            return error;
        }

        /* allocate 4M untyped for constructing a 2-level vbtree */
        cookie = allocman_utspace_alloc(alloc, 22, seL4_UntypedObject, &src_slot, false, &error);
        if (error) {
            allocman_cspace_free(alloc, &src_slot);
            return error;
        }
        /* retrieve paddr --> useful for query if paddr is specified */
        paddr = allocman_utspace_paddr(alloc, cookie, 22);

        ptr_tree = (vbtree_t *)allocman_mspace_alloc(alloc, sizeof(vbtree_t), &error);
        if (error) {
            ZF_LOGE("Failed to alloc metadata to keep vbt-tree info.");
            allocman_cspace_free(alloc, &src_slot);
            allocman_utspace_free(alloc, cookie, 22);
            return error;
        }
        memset(ptr_tree, 0, sizeof(vbtree_t));

        /* create space for the newly created capabilities */
        error = allocman_cspace_csa(alloc, &des_slot, 10);
        if (error) {
            ZF_LOGE("Failed to alloc contiguous slots for pre-allocated frames.");
            allocman_cspace_free(alloc, &src_slot);
            allocman_utspace_free(alloc, cookie, 22);
            allocman_mspace_free(alloc, ptr_tree, sizeof(vbtree_t));
            return error;
        }

        vka_object_t origin = {src_slot.capPtr, cookie, seL4_UntypedObject, 22};
        error = vka_untyped_retype(&origin, seL4_ARCH_4KPage, seL4_PageBits, BIT(10), &des_slot);
        if (error) {
            ZF_LOGE("[ERROR]: FAILED TO RETYPE CONTIGUOUS 4K PAGES.");
            return error;
        }

        vbt_tree_init(alloc, ptr_tree, paddr, src_slot.capPtr, des_slot, 22);
        vbt_tree_list_insert(&alloc->frame_pool.mem_treeList[10], ptr_tree);

        /* for retrieving the dest tree to free a frame with cptr */
        error = _allocman_utspace_append_tcookie(alloc, ptr_tree);
        if (error) {
            /* ? */
            ZF_LOGE("Failed to append new node into the vbtree cookie list");
            return error;
        }
    }
    size_t curr_blk_size = ptr_tree->blk_cur_size;
    vbtspacepath_t blk = {0, 0};
    
    vbt_tree_query_blk(ptr_tree, size_bits, &blk, ALLOCMAN_NO_PADDR);
    slot = vbt_tree_acq_cap_idx(ptr_tree, &blk) + ptr_tree->frames_cptr_base;    
    vbt_tree_release_blk_from_vbt_tree(ptr_tree, &blk);

    if (ptr_tree->blk_cur_size != curr_blk_size) {
        vbt_tree_list_remove(&alloc->frame_pool.mem_treeList[curr_blk_size - seL4_PageBits], ptr_tree);

        if (ptr_tree->blk_cur_size != 0) {
            vbt_tree_list_insert(&alloc->frame_pool.mem_treeList[ptr_tree->blk_cur_size - seL4_PageBits], ptr_tree);
        } else {
            if (ptr_tree->prev) {
                ptr_tree->prev->next = ptr_tree->next;
            }
            if (ptr_tree->next) {
                ptr_tree->next->prev = ptr_tree->prev;
            }
            ptr_tree->prev = NULL;
            ptr_tree->next = NULL;
        }
    }
    /* make path for the starting cptr */
    *res = allocman_cspace_make_path(alloc, slot);

    /* several pages retrieved */
    if (size_bits != seL4_PageBits)
        res->window = BIT(size_bits - seL4_PageBits);

    return 0;
}

void allocman_utspace_try_free_from_pool(allocman_t *alloc, seL4_CPtr cptr)
{
    assert(alloc->frame_pool.tcookieList);
    
    tcookie_t *tck = alloc->frame_pool.tcookieList;
    
    for (; tck && cptr > (tck->cptr + 1023); tck = tck->next);

    assert(cptr >= tck->cptr);
    assert(cptr < tck->cptr + 1024);

    vbtree_t *target = tck->tptr;
    size_t blk_cur_size = target->blk_cur_size;
    size_t global = cptr - target->frames_cptr_base;
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

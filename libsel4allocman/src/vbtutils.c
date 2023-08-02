
#include <allocman/vbtutils.h>

#define VBT_NO_PADDR 1

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

void vbt_tree_init(virtual_bitmap_tree_t *target_tree, uintptr_t paddr, cspacepath_t frame_cptr_sequence, size_t real_size)
{
    target_tree->paddr = paddr;
    target_tree->frame_sequence = frame_cptr_sequence;
    target_tree->blk_max_size = real_size;
    target_tree->blk_cur_size = real_size;

    size_t size_bits = real_size - VBT_PAGE_GRAIN;
    assert(size_bits && size_bits <= 10);
    if (size_bits < BITMAP_LEVEL) {
        target_tree->entry.toplevel = 32;
        target_tree->entry.sublevel = VBT_SUBLEVEL_INDEX(size_bits);
        target_tree->top_tree.tnode[0] |= VBT_INDEX_BIT(32);
        target_tree->sub_trees[0].tnode[0] |= VBT_INDEX_BIT(target_tree->entry.sublevel);
        target_tree->sub_trees[0].tnode[0] |= vbt_tree_sub_add_up(target_tree->entry.sublevel);
    } else {
        target_tree->entry.toplevel = VBT_TOPLEVEL_INDEX(size_bits);
        target_tree->top_tree.tnode[0] |= VBT_INDEX_BIT(target_tree->entry.toplevel);
        target_tree->top_tree.tnode[0] |= vbt_tree_sub_add_up(target_tree->entry.toplevel);
        int window = vbt_tree_window_at_level(BITMAP_DEPTH, target_tree->entry.toplevel);
        int idx = BITMAP_SUB_OFFSET(window * target_tree->entry.toplevel);
        for (int i = idx; i < idx + window; ++i) {
            if (VBT_AND(target_tree->top_tree.tnode[0], VBT_INDEX_BIT(i))) {
                target_tree->sub_trees[i].tnode[0] = (uint64_t)-1;
                target_tree->sub_trees[i].tnode[0] &= MASK(63);
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

    if (paddr != VBT_NO_PADDR) {
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
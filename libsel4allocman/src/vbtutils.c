
#include <autoconf.h>
#include <allocman/vbtutils.h>
#include <allocman/allocman.h>

static inline int vbt_bitmap_offspring_layer_magnification(int anc_layer, int offs_layer) {
    return 1ul << (offs_layer - anc_layer);
}

static inline int vbt_tree_ibidx_at(int target_layer, int index) {
    return (1ul<<(target_layer - BITMAP_GET_LEVEL(index)))*index;
}

static size_t vbt_bitmap_offspring_count(int index)
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

    tree->blk_max_size = BIT(real_size);
    tree->blk_cur_size = BIT(real_size);

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
        tree->sub_trees[0].tnode[0] |= vbt_bitmap_offspring_count(tree->entry.sublevel);
    } else {
        tree->entry.toplevel = VBT_TOPLEVEL_INDEX(size_bits);
        tree->top_tree.tnode[0] |= VBT_INDEX_BIT(tree->entry.toplevel);
        tree->top_tree.tnode[0] |= vbt_bitmap_offspring_count(tree->entry.toplevel);
        int idx = vbt_tree_ibidx_at(BITMAP_DEPTH, tree->entry.toplevel);
        for (int i = idx; i < idx << 1; ++i) {
            if (VBT_AND(tree->top_tree.tnode[0], VBT_INDEX_BIT(i))) {
                tree->sub_trees[BITMAP_SUB_OFFSET(i)].tnode[0] = (size_t)-1;
                tree->sub_trees[BITMAP_SUB_OFFSET(i)].tnode[0] &= MASK(64);
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
        for (int i = BITMAP_SIZE >> 1; i < BITMAP_SIZE && !(res->sublevel); ++i) {
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

inline seL4_CPtr vbt_tree_acq_cap_idx(struct vbt_tree *tree, const vbtspacepath_t *path) {
    return (path->sublevel - 32) + (tree->entry.toplevel < 32 ? 0 : 32 * (path->toplevel - tree->entry.toplevel));
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
    bitmap->tnode[0] &= ~vbt_bitmap_offspring_count(index);
    bitmap->tnode[0] &= ~(VBT_INDEX_BIT(index));
}

void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path) {
    struct vbt_tree *tree = (struct vbt_tree*)_tree;
    struct vbt_bitmap *topl = &tree->top_tree;
    struct vbt_bitmap *subl = NULL;

    if (!path->sublevel) {
        vbt_tree_release_blk_from_bitmap(topl, path->toplevel);
        int idx_sub_tree = vbt_tree_ibidx_at(BITMAP_DEPTH, path->toplevel);
        for (int i = idx_sub_tree; i < idx_sub_tree << 1; ++i) {
            if (!VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                tree->sub_trees[BITMAP_SUB_OFFSET(i)].tnode[0] = 0ul;
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
    int ruler = 0;
    int temp = 0;
    int new_max = CLZL(topl->tnode[0]);
    int new_lyr = BITMAP_GET_LEVEL(new_max);
    if (new_max >= 32) {
        for (int i = new_max; i < BITMAP_SIZE - CTZL(topl->tnode[0]); ++i) {
            if (VBT_AND(topl->tnode[0], VBT_INDEX_BIT(i))) {
                temp = CLZL(MASK(64) & tree->sub_trees[BITMAP_SUB_OFFSET(i)].tnode[0]);
                if (temp > ruler) {
                    ruler = temp;
                }
            }
        }
        tree->blk_cur_size = BIT((BITMAP_DEPTH) - BITMAP_GET_LEVEL(ruler) + (VBT_PAGE_GRAIN));
    } else {
        tree->blk_cur_size = BIT((BITMAP_DEPTH) - new_lyr + (BITMAP_LEVEL) + (VBT_PAGE_GRAIN));
    }
}

void vbt_tree_insert(struct vbt_tree **treeList, struct vbt_tree *tree)
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
    }
}

int vbt_acq_frame_from_pool(struct vbt_forrest *pool, size_t real_size, seL4_CPtr *res)
{
    int i = 0;
    vbtspacepath_t blk = {0, 0};
    size_t size_bits = real_size - 12;
    assert(size_bits == 0);

    for (; !pool->mem_treeList[i] && i < 11; ++i);

    if (i == 11) {
        return 1;
    }

    struct vbt_tree *tree = pool->mem_treeList[i];

    vbt_tree_query_blk(tree, 12, &blk, ALLOCMAN_NO_PADDR);
    *res = vbt_tree_acq_cap_idx(tree, &blk) + tree->pool_range.capPtr;
    vbt_tree_release_blk_from_vbt_tree(tree, &blk);

    vbt_tree_insert(&pool->mem_treeList[tree->blk_cur_size], tree);

    return 0;
}



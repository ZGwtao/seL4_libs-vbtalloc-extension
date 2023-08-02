
#pragma once

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <stdint.h>

#define BITMAP_DEPTH            6
#define BITMAP_SIZE             64
#define BITMAP_SUB_OFFSET(X)    ((X) - 32)
#define BITMAP_LEVEL            ((BITMAP_DEPTH) - 1)
#define VBT_PAGE_GRAIN          seL4_PageBits
#define VBT_INDEX_BIT(X)        BIT(((BITMAP_SIZE) - 1) - (X))
#define BITMAP_GET_LEVEL(X)     ((BITMAP_SIZE) - CLZL(X))
#define BITMAP_INDEX(SZ)        (1 << ((BITMAP_LEVEL) - (SZ)))
#define VBT_SUBLEVEL_INDEX(SZ)  BITMAP_INDEX(SZ)
#define VBT_TOPLEVEL_INDEX(SZ)  BITMAP_INDEX((SZ) - (BITMAP_LEVEL))
#define VBT_AND(WORDA,WORDB)    ((WORDA) & (WORDB))
#define VBT_ORR(WORDA,WORDB)    ((WORDA) | (WORDB))

typedef struct vbtspacepath {
    int toplevel;
    int sublevel;
} vbtspacepath_t; 

struct vbt_bitmap {
    uint64_t tnode[1];
};

typedef struct virtual_bitmap_tree {
    uintptr_t       paddr;
    vbtspacepath_t  entry;
    cspacepath_t    frame_sequence;
    size_t          blk_max_size;
    size_t          blk_cur_size;
    struct virtual_bitmap_tree *next, *prev;
    struct vbt_bitmap top_tree;
    struct vbt_bitmap sub_trees[32];
} virtual_bitmap_tree_t;

typedef struct virtual_bitmap_tree_cookie {
    /***
     * @param: 'frames_cptr_base' can be used to sort all virtual-bitmap-trees in
     *          the tree_cookie_linked_list, this is because it's not always easy
     *          to retrieve deep down to the virtual_bitmap_tree_t as they can be
     *          different under different machine words working environments
     */
    seL4_CPtr frames_cptr_base;
    /***
     * pointer to the cookie of the target_tree's metadata
     */
    virtual_bitmap_tree_t *target_tree;
    /***
     * bi-directions linked-list of tree_cookies
     */
    struct virtual_bitmap_tree_cookie *prev;
    struct virtual_bitmap_tree_cookie *next;
} virtual_bitmap_tree_cookie_t;

typedef struct capbuddy_memory_pool {
    virtual_bitmap_tree_t *cell[11];
    virtual_bitmap_tree_t *useup;
    virtual_bitmap_tree_cookie_t *cookie_linked_list;
} capbuddy_memory_pool_t;

void vbt_tree_init(virtual_bitmap_tree_t *target_tree, uintptr_t paddr, cspacepath_t frame_cptr_sequence, size_t real_size);
void vbt_tree_query_blk(virtual_bitmap_tree_t *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr);
seL4_CPtr vbt_tree_acq_cap_idx(virtual_bitmap_tree_t *tree, const vbtspacepath_t *path);
void vbt_tree_restore_blk_from_bitmap(void *_bitmap, int index);
void vbt_tree_release_blk_from_bitmap(void *_bitmap, int index);
void vbt_tree_update_avail_size(virtual_bitmap_tree_t *tree);
void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path);
void vbt_tree_restore_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path);
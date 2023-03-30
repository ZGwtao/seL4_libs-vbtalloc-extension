
#pragma once

#include <sel4/sel4.h>
#include <vka/vka.h>

#define VBT_MAX_BLK_SZBTS       22
#define VBT_PAGE_GRAIN          seL4_PageBits
#define VBT_RETYPE_EPOCH        CONFIG_RETYPE_FAN_OUT_LIMIT

#define BITMAP_DEPTH            6
#define BITMAP_SIZE             BIT(BITMAP_DEPTH)
#define BITMAP_SUB_OFFSET(X)    ((X) - (BITMAP_SIZE >> 1))

#define BITMAP_LEVEL            ((BITMAP_DEPTH) - 1)
#define BITMAP_REMAIN           ((BITMAP_SIZE) - (BITMAP_DEPTH))
#define VBT_INDEX_BIT(X)        BIT(((BITMAP_SIZE) - 1) - (X))

#define BITMAP_GET_LEVEL(X)     (CONFIG_WORD_SIZE - CLZL(X))
#define BITMAP_CAL_NOFFS(L1,L2) BIT((L2) - (L1))

#define VBT_SUBTREE_PER_TREE    ((BITMAP_SIZE) >> 1)
#define BITMAP_NUM_BOTTOM_UNIT  ((BITMAP_SIZE) >> 1)

#define VBT_VALID(NWORD)        VBT_AND((NWORD), (BIT(BITMAP_SIZE - 1)))

#define BITMAP_INDEX(SZ)        (1 << ((BITMAP_LEVEL) - (SZ)))
#define VBT_SUBLEVEL_INDEX(SZ)  BITMAP_INDEX(SZ)
#define VBT_TOPLEVEL_INDEX(SZ)  BITMAP_INDEX((SZ) - (BITMAP_LEVEL))

#define VBT_TREE_FRAME_PER_TREE ((VBT_SUBTREE_PER_TREE) * (BITMAP_NUM_BOTTOM_UNIT))
#define VBT_VIRT_FREE_LIST_SIZE 11
#define VBT_REAL_FREE_LIST_SIZE CONFIG_WORD_SIZE
#define VBT_AND(WORDA,WORDB)    ((WORDA) & (WORDB))
#define VBT_ORR(WORDA,WORDB)    ((WORDA) | (WORDB))

typedef struct vbtspacepath {
    int toplevel;
    int sublevel;
} vbtspacepath_t; 

struct vbt_bitmap {
    size_t tnode[1];
};

struct vbt_tree {
    uintptr_t       paddr;
    vbtspacepath_t  entry;
    cspacepath_t    origin;
    cspacepath_t    pool_range;
    size_t          blk_max_size;
    size_t          blk_cur_size;
    struct vbt_tree *next, *prev;
    struct vbt_bitmap top_tree;
    struct vbt_bitmap sub_trees[32];
};

struct vbt_forrest {
    struct vbt_tree *mem_treeList[11];
};

typedef struct vbt_forrest vbt_pool_t;

struct allocman;

void vbt_tree_init(struct allocman *alloc, struct vbt_tree *tree, uintptr_t paddr, seL4_CPtr origin, cspacepath_t dest_reg, size_t real_size);
void vbt_tree_query_blk(struct vbt_tree *tree, size_t real_size, vbtspacepath_t *res, uintptr_t paddr);
void vbt_tree_release_blk_from_vbt_tree(void *_tree, const vbtspacepath_t *path);
void vbt_tree_insert(struct vbt_tree **treeList, struct vbt_tree *tree);
int vbt_acq_frame_from_pool(struct vbt_forrest *pool, size_t real_size, seL4_CPtr *res);

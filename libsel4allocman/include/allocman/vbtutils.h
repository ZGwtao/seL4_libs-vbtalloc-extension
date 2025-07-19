
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

typedef struct vbt_tree {
    uintptr_t       paddr;
    vbtspacepath_t  entry;
    cspacepath_t    origin;
    cspacepath_t    pool_range;
    size_t          blk_max_size;
    size_t          blk_cur_size;
    struct vbt_tree *next, *prev;
    struct vbt_bitmap top_tree;
    struct vbt_bitmap sub_trees[32];
} vbtree_t;

typedef struct tcookie {
    seL4_CPtr cptr;
    vbtree_t *tptr;
    struct tcookie *prev;
    struct tcookie *next;
} tcookie_t;

struct vbt_forrest {
    vbtree_t *mem_treeList[11];
    tcookie_t *tcookieList;
};

typedef struct vbt_forrest vbt_pool_t;

struct allocman;
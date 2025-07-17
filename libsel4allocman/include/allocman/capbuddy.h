
#pragma once

#include <autoconf.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <stdint.h>
#include <allocman/vbt.h>
#include <utils/sglib.h>

/* number of cookie, each for a tree -> 4MB/tree */
#define MAX_COOKIE_NUM  1024

#define DEFINE_NODE_VBTREE(NAME,TYPE,ATTR) \
    typedef struct NAME {   \
        TYPE ATTR;          \
        vbt_t *target_tree; \
        char color_field;   \
        struct NAME *left;  \
        struct NAME *right; \
    } NAME;

DEFINE_NODE_VBTREE(node_vbtree, seL4_CPtr, frames_cptr_base)

typedef struct capbuddy_memory_pool {
    vbt_t *cell[11];
    /* try replace O(n) list with O(logn) for searching */
    node_vbtree *cookie_rb_tree;
    /* paddr O(1) search map */
    vbt_t *cookie_map[MAX_COOKIE_NUM];
} capbuddy_memory_pool_t;

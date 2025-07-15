
#pragma once

#include <autoconf.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <stdint.h>
#include <allocman/vbt.h>
#include <utils/sglib.h>

typedef struct node_vbtree {
    /***
     * @param: 'frames_cptr_base' can be used to sort all virtual-bitmap-trees in
     *          the cookie red-black tree >>, this is because it's not always easy
     *          to retrieve deep down to the vbt_t as they can be different under
     *          different machine words working environments
     */
    seL4_CPtr frames_cptr_base;
    /***
     * start physical address of all frames
     *   end physical address of all frames
     */
    uintptr_t paddr_head;
    uintptr_t paddr_tail;
    /***
     * pointer to the cookie of the target_tree's metadata
     */
    vbt_t *target_tree;
    /***
     * bi-directions linked-list of tree_cookies
     */
    
    char color_field;
    struct node_vbtree *left;
    struct node_vbtree *right;
} node_vbtree;

typedef struct capbuddy_memory_pool {
    vbt_t *cell[11];
    /* try replace O(n) list with O(logn) for searching */
    node_vbtree *cookie_rb_tree;
} capbuddy_memory_pool_t;

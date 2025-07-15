
#pragma once

#include <autoconf.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <stdint.h>
#include <allocman/vbt.h>
#include <utils/sglib.h>

typedef struct cookie_tree {
    /***
     * @param: 'frames_cptr_base' can be used to sort all virtual-bitmap-trees in
     *          the tree_cookie_linked_list, this is because it's not always easy
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
    struct cookie_tree *left;
    struct cookie_tree *right;
} cookie_tree;

static inline int cookie_cmp(cookie_tree *x, cookie_tree *y)
{
    if (x->frames_cptr_base < y->frames_cptr_base) {
        return -1;
    }
    if (x->frames_cptr_base == y->frames_cptr_base) {
        return 0;
    }
    return 1;
}

SGLIB_DEFINE_RBTREE_PROTOTYPES(cookie_tree, left, right, color_field, cookie_cmp);
SGLIB_DEFINE_RBTREE_FUNCTIONS(cookie_tree, left, right, color_field, cookie_cmp);

typedef struct capbuddy_memory_pool {

    vbt_t *cell[11];

    vbt_t *useup;

    /* try replace O(n) list with O(logn) for searching */
    cookie_tree *cooke_rb_tree;

} capbuddy_memory_pool_t;

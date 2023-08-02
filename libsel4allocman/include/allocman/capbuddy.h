
#pragma once

#include <autoconf.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <stdint.h>
#include <allocman/vbt.h>

typedef struct virtual_bitmap_tree_cookie {
    /***
     * @param: 'frames_cptr_base' can be used to sort all virtual-bitmap-trees in
     *          the tree_cookie_linked_list, this is because it's not always easy
     *          to retrieve deep down to the vbt_t as they can be different under
     *          different machine words working environments
     */
    seL4_CPtr frames_cptr_base;
    /***
     * pointer to the cookie of the target_tree's metadata
     */
    vbt_t *target_tree;
    /***
     * bi-directions linked-list of tree_cookies
     */
    struct virtual_bitmap_tree_cookie *prev;
    struct virtual_bitmap_tree_cookie *next;
} vbt_cookie_t;

typedef struct capbuddy_memory_pool {

    vbt_t *cell[11];

    vbt_t *useup;

    vbt_cookie_t *cookie_linked_list;

} capbuddy_memory_pool_t;

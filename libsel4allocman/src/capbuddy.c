
#include <autoconf.h>
#include <allocman/allocman.h>
#include <allocman/util.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sel4/sel4.h>
#include <vka/capops.h>
#include <sel4utils/util.h>

#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS /* CapBuddy support */

static inline int cookie_cmp(node_vbtree *x, node_vbtree *y)
{
    if (x->frames_cptr_base == y->frames_cptr_base) {
        return 0;
    }
    if (x->frames_cptr_base > y->frames_cptr_base) {
        if (x->frames_cptr_base < y->frames_cptr_base + 1024) {
            return 0;
        }
        return 1;
    }
    return -1;
}

SGLIB_DEFINE_RBTREE_PROTOTYPES(node_vbtree, left, right, color_field, cookie_cmp);
SGLIB_DEFINE_RBTREE_FUNCTIONS(node_vbtree, left, right, color_field, cookie_cmp);

static node_vbtree *find_vbt_tree_by_cptr(node_vbtree *cookie_rb_tree, seL4_CPtr fcptr)
{
    node_vbtree *result_node;
    if (!cookie_rb_tree) {
        ZF_LOGE("Failed to find target vbt tree from cookie: CapBuddy Cookie List Invalid");
        return NULL;
    }
    node_vbtree search_node;
    search_node.frames_cptr_base = fcptr;
    
    /* 0 means match, search with base cptr */
    result_node = sglib_node_vbtree_find_member(cookie_rb_tree, &search_node);
    return result_node;
}

/* FIXME: no delete node in vbt cookie rbtree? */
static void remove_vbt_tree_node(node_vbtree *cookie_rb_tree, node_vbtree *todel_node)
{
    node_vbtree *result_node;
    if (!cookie_rb_tree) {
        ZF_LOGE("Failed to find target vbt tree from cookie: CapBuddy Cookie List Invalid");
        return;
    }
    result_node = sglib_node_vbtree_find_member(cookie_rb_tree, todel_node);
    if (!result_node) {
        /* No node found */
        ZF_LOGE("Failed to find target vbt tree to delete");
        return;
    }
    sglib_node_vbtree_delete(&cookie_rb_tree, result_node);
}

static int add_vbt_tree_node(node_vbtree **pcookie_rb_tree, node_vbtree *new_node)
{
    node_vbtree *result_node;
    if (!new_node) {
        ZF_LOGE("Failed to add vbt tree to cookie rbtree: Initialise the New Node First!");
        return -1;
    }
    
    result_node = sglib_node_vbtree_find_member(*pcookie_rb_tree, new_node);
    if (result_node) {
        /* found, no need to add */
        ZF_LOGE("Failed to add new vbtree node: Given node already exists");
        return -1;
    }

    sglib_node_vbtree_add(pcookie_rb_tree, new_node);
    return 0;
}

static void _capbuddy_linked_list_insert(vbt_t *tree_linked_list[], vbt_t *target_tree)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(target_tree);
#endif
    /* Initialize list firstly */
    if ((*tree_linked_list) == NULL) {
        /* Remove it from the original list */
        if (target_tree->next) {
            target_tree->next->prev = target_tree->prev;
        }
        if (target_tree->prev) {
            target_tree->prev->next = target_tree->next;
        }
        /* Initialization */
        target_tree->next = NULL;
        target_tree->prev = NULL;
        /* Binding */
        *tree_linked_list = target_tree;
        return;
    }

    vbt_t *head = *tree_linked_list;
    vbt_t *curr = head;

#undef TREE_NODE_COMPARE
#define TREE_NODE_COMPARE(p1,p2,cmp) \
    (p1->frame_sequence.capPtr cmp p2->frame_sequence.capPtr)

    /* Retrieve target insertion point */
    while (curr) {
        if (TREE_NODE_COMPARE(curr, target_tree, >=)) {
            break;
        }
        if (!curr->next) {
            break;
        }
        curr = curr->next;
    }
    /* If target_tree should line at the end of the list */
    if (TREE_NODE_COMPARE(curr, target_tree, <)) {
        target_tree->prev = curr;
        if (curr->next) {
            target_tree->next = curr->next;
            curr->next->prev = target_tree;
        }
        curr->next = target_tree;
        return;
    }
    /***
     * curr_prev <- target_tree <- curr, in that order
     */
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(TREE_NODE_COMPARE(curr, target_tree, >));
#endif
    target_tree->next = curr;
    if (curr->prev) {
        target_tree->prev = curr->prev;
        curr->prev->next = target_tree;
    }
    curr->prev = target_tree;
    /* Should be the first one */
    if (TREE_NODE_COMPARE(head, target_tree, >)) {
        *tree_linked_list = target_tree;
    }
#undef TREE_NODE_COMPARE
}

static void _capbuddy_linked_list_remove(vbt_t *tree_linked_list[], vbt_t *target_tree)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(target_tree);
    assert(tree_linked_list);
#endif
    vbt_t *head = *tree_linked_list;
    vbt_t *curr = head;

    /* Retrieve target_tree from target list */
    while (curr) {
        if (target_tree == curr) {
            break;
        }
        curr = curr->next;
    }
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Check if no error occurs */
    assert(target_tree == curr);
#endif
    /* Remove it from the list */
    if (curr->prev != NULL) {
        curr->prev->next = curr->next;
    }
    if (curr->next != NULL) {
        curr->next->prev = curr->prev;
    }
    /* If we are cutting the head down */
    if (head == curr) {
        *tree_linked_list = curr->next;
    }
    curr->next = NULL;
    curr->prev = NULL;
    return;
}

static int _capbuddy_try_acquire_multiple_frames_at(allocman_t *alloc, uintptr_t paddr, size_t real_size, seL4_CPtr *res)
{
    if (!alloc) {
        ZF_LOGE("No allocator is given");
        return -1;
    }
    if (&alloc->utspace_capbuddy_memory_pool == NULL) {
        ZF_LOGE("No capbuddy memory pool is given");
        return -1;
    }
    capbuddy_memory_pool_t *pool = (capbuddy_memory_pool_t *)(&alloc->utspace_capbuddy_memory_pool);

#undef TREE_COOKIE_DETERMINE_PADDR
#define TREE_COOKIE_DETERMINE_PADDR(tptr, paddr) \
    ((tptr->paddr_head <= paddr) && (tptr->paddr_tail > paddr))

#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Make sure the arg 'real_size' of the requested memory region is legal */
    assert(real_size >= seL4_PageBits);
#endif
    /***
     * Try getting the first available virtual-bitmap-tree.
     * The tree must have no less than one piece of available memory region
     * that is large enough to meet the memory request (avail_size > real_size)
     */
    vbt_t *target_tree = NULL;

    size_t idx = /* memory pool is sorted by frame number (in bits) of the largest available memory region */
        real_size - seL4_PageBits;  /* 0, 1, 2, 4, ..., 256, 512, 1024 (2^0~10) frames */

    if (paddr == ALLOCMAN_NO_PADDR) {
        while (idx <= 10) {
            /***
             * As described above, 0 <= idx <= 10, and every unit in memory pool represents
             * a linked-list for the virtual-bitmap-trees with largest available memory region
             * of size 2^idx frames. Since no paddr is required, the query method is FCFS
             */
            target_tree = pool->cell[idx++];
            if (target_tree) {
                break;
            }
        }
        /* align */
        idx -= 1;
    } else {
        /***
         * sorted by cptr, so give pool->cell up and search it with paddr in cookie list
         */
        node_vbtree *tck = pool->cookie_rb_tree;

        // FIXME
        while (1);
        /* If already allocated */
        if (tck) {
            target_tree = tck->target_tree;
            /***
             * FIXME:
             *  idx can be deprecated here. Use 'largest_avail'
             *  instead and it will be fine.
             */
            idx = target_tree->largest_avail - seL4_PageBits;
        }
    }

    if (target_tree == NULL) {
        /* Failed to find available tree from CapBuddy's memory pool */
        ZF_LOGV("No available virtual-bitmap-tree has enough memory for %ld memory request", BIT(real_size));
        return -1;
    }

    /***
     * path to the available memory region in a virtual-bitmap-tree
     */
    void *cookie = NULL;
    int err = -1;
    /***
     * Try getting the location of a available memory region from the target_tree.
     * A target_tree may have more than one available memory region to serve the
     * memory requested, so we need to find the first one.
     */
    if (paddr != ALLOCMAN_NO_PADDR) {
        cookie = vbt_query_avail_memory_region_at(alloc, target_tree, real_size, paddr, &err);
    } else {
        cookie = vbt_query_avail_memory_region(alloc, target_tree, real_size, &err);
    }
    if (err != seL4_NoError) {
        ZF_LOGV("Failed to query cookie in a virtual-bitmap-tree: [%08x], %d", paddr, real_size);
        return err;
    }

    vbt_update_memory_region_acquired(target_tree, cookie);
    /***
     * Since 'res' denotes the first frame of the memory region to serve the request,
     * typically in capability-index form, we should calculate the cptr of the frame
     * and set it with the cptr.
     * NOTICE:
     *  [1][2][3][4] <- if we want [3], we should calculate it this way:
     * 
     *  base = cptr_of([1]), offset = 3 - 1, result = base + offset = cptr_of([1]) + 2
     * ------------------------------------------------------------------------------------
     * This works when we are in single level cspace, it should also be able to implemented
     * under other cspace structure. Another thing: frames (from Untyped_Retype) are linearly
     * distributing, so their capability index also construct a linear space (and it's fine
     * to be addressed by this convention: base + offset )
     * ------------------------------------------------------------------------------------
     */
    *res = target_tree->frame_sequence.capPtr + /* the first frame among the whole memory region managing by the tree */
                vbt_calculate_target_frame_cptr_offset(target_tree, cookie); /* base + offset, so this is the offset */

    vbt_query_try_cookie_release(alloc, cookie);

    if (target_tree->largest_avail == (idx + seL4_PageBits)) {
        /***
         * Only happens when target_tree has more than 1 available
         * memory region to serve the memory request, which means
         * the updated tree status does not changed
         */
        return seL4_NoError;
    }
    
    /* Remove it from the original tree list of memory pool */
    _capbuddy_linked_list_remove(&pool->cell[idx], target_tree);

    /***
     * If the updated virtual-bitmap-tree still has available memory region
     * to meet other memory requests, we need to add it back to the memory
     * pool, otherwise add it to the 'empty' list.
     */
    if (target_tree->largest_avail != 0) {
        /***
         * It the updated virtual-bitmap-tree has a different maximum available
         * memory region size, we need to insert it into a new tree linked-list.
         */
        idx = target_tree->largest_avail - seL4_PageBits;
        /* do the insertion */
        _capbuddy_linked_list_insert(&pool->cell[idx], target_tree);
        return seL4_NoError;
    }
    /* Released from original list */
    if (target_tree->next) {
        target_tree->next->prev = target_tree->prev;
    }
    if (target_tree->prev) {
        target_tree->prev->next = target_tree->next;
    }
    /* Initialization */
    target_tree->next = NULL;
    target_tree->prev = NULL;
    return seL4_NoError;

#undef TREE_COOKIE_DETERMINE_PADDR
}

static int _allocman_cspace_csa(allocman_t *alloc, cspacepath_t *slots, size_t num_bits)
{
    int err = -1;
    /* Don't invoke it when nothing exists */
    if (!alloc->have_cspace) {
        return err;
    }
    err = alloc->cspace.csa(alloc, alloc->cspace.cspace, slots, num_bits);
    return err;
}

/***
 *  This is just one wrapper function for the internal implementation
 *  of allocman's cspace_csa function '_allocman_cspace_csa(...)'
 * 
 * @note: csa = [c]ontiguous capability-[s]lots' pointers' [a]llocation
 * @param: alloc : the allocator to be invoked (allocman-allocator)
 * @param: slots : destination slots to fill in
 * @param: num_bits : how many capabilities slots you wish to mark as allocated
 */
int allocman_cspace_csa(allocman_t *alloc, cspacepath_t *slots, size_t num_bits)
{
    /* Call the internal function of allocman */
    return _allocman_cspace_csa(alloc, slots, num_bits);
}

static int _allocman_utspace_append_virtual_bitmap_tree_cookie(allocman_t *alloc, vbt_t *tree)
{
#undef TREE_COOKIE_COMPARE_CPTR
#define TREE_COOKIE_COMPARE_CPTR(c1, c2, cmp) \
    (c1->frames_cptr_base cmp c2->frames_cptr_base)

    int err;
    node_vbtree *tx;
    /* Allocate space for new cookie's metadata */
    tx = (node_vbtree *)allocman_mspace_alloc(alloc, sizeof(node_vbtree), &err);
    if (!tx || err) {
        /* Failed to alloc new tree_cookie */
        return -1;
    }
    tx = (node_vbtree *)memset(tx, 0, sizeof(node_vbtree));

    tx->paddr_head = tree->base_physical_address;
    tx->paddr_tail = tree->base_physical_address + (1U << 22); /* 12 page_size + 10 page_num */
    tx->frames_cptr_base = tree->frame_sequence.capPtr;
    tx->target_tree = tree;

    err = add_vbt_tree_node(&alloc->utspace_capbuddy_memory_pool.cookie_rb_tree, tx);
    if (err) {
        ZF_LOGE("Failed to add new vbt tree to the cookie rbtree");
        return err;
    }
    return seL4_NoError;
#undef TREE_COOKIE_COMPARE_CPTR
}

static void _allocman_utspace_subtract_virtual_bitmap_tree_cookie(allocman_t *alloc, seL4_CPtr fbcptr)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(alloc->utspace_capbuddy_memory_pool.cookie_rb_tree);
#endif
    node_vbtree *tck;
    /* Try retrieving target virtual-bitmap-tree */
    tck = find_vbt_tree_by_cptr(alloc->utspace_capbuddy_memory_pool.cookie_rb_tree, fbcptr);
    if (!tck) {
        /* internal capbuddy allocator error */
        assert(0);
    }
    vbt_t *target = tck->target_tree;

    if (target != NULL) {
        assert(target->largest_avail);
        _capbuddy_linked_list_remove(&alloc->utspace_capbuddy_memory_pool.cell[target->largest_avail - seL4_PageBits], target);
        allocman_mspace_free(alloc, target, sizeof(vbt_t));
    }

    sglib_node_vbtree_delete(alloc->utspace_capbuddy_memory_pool.cookie_rb_tree, tck);
    allocman_mspace_free(alloc, tck, sizeof(node_vbtree));
}

int allocman_utspace_try_create_virtual_bitmap_tree(allocman_t *alloc, const cspacepath_t *ut, size_t fn, uintptr_t paddr)
{
    int err = -1;
    if (!alloc->have_utspace) {
        return err;
    }
    /***
     * constant values to create a new virtual-bitmap-tree (configurable)
     */
    size_t frames_window_bits = fn; /* support 1024 now only */
    size_t frames_window_size = BIT(frames_window_bits);
    size_t memory_region_bits = frames_window_bits + seL4_PageBits;
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(frames_window_bits == 10);
#endif
    vbt_t *target_tree;
    /***
     * FIXME:
     *  What heap manager interface should be called here to store the virtual-bitmaps-
     *  tree's metadata? 'allocman_mspace_alloc' or 'malloc'->sel4muslibcsys? I think
     *  both of them are allocated from the '.bss' section during allocator's bootstrap.
     */
    target_tree = (vbt_t *)allocman_mspace_alloc(alloc, sizeof(vbt_t), &err);
    if (!target_tree || err) {
        ZF_LOGE("Failed to allocate metadata to bookkeep vbt-tree information");
        return err;
    }
    target_tree = (vbt_t *)memset(target_tree, 0, sizeof(vbt_t));

    target_tree->mark = 1;

    /***
     * @param: frame_cptr_sequence: records the compressed metadata of frames of the
     *         requested memory region (described at the entry of this function).
     */
    cspacepath_t frame_cptr_sequence;
    /*** 
     * @note: csa = [c]ontiguous capability-[s]lots' pointers' [a]llocation
     * 
     *  Here we try allocating metadata for the requested frames from the user-level
     *  cspace allocator, 'allocman_cspace_csa' is enabled when CapBuddy supports are
     *  enabled too.
     */
    err = allocman_cspace_csa(alloc, &frame_cptr_sequence, frames_window_bits);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to allocate contiguous slots for frames of the requested memory region");
        allocman_mspace_free(alloc, target_tree, sizeof(vbt_t));
        return err;
    }

    err =
        seL4_Untyped_Retype(
            ut->capPtr,    /* '_service' : original untyped object cptr */
            seL4_ARCH_4KPage,           /* 'type' : target object type it retypes to */
            seL4_PageBits,              /* 'size' : target object size it retypes to */
            frame_cptr_sequence.root,       // [dest] -> cspace root to find the frame caps
            frame_cptr_sequence.dest,       // [dest] -> target cnode capability index (cptr)
            frame_cptr_sequence.destDepth,  // [dest] -> cnode depth to retrieve the cspace
            frame_cptr_sequence.offset,     // [dest] -> first frame capability index (cptr)
            frames_window_size          /* 'num_objects' : frame number from the requested memory region */
        );
    if (err != seL4_NoError) {
        /* Failed to retype to new frames through kernel interface from libsel4 */
        ZF_LOGE("Failed to invoke 'seL4_Untyped_Retype' to create frames for CapBuddy memory pool");
        return err;
    }

    /***
     * When every thing is ready, let's put the newly created virtual-bitmap-tree into
     * CapBuddy's memory pool, and of course, we need to initialize a metadata for it.
     */
    err = vbt_instance_init(alloc, target_tree, paddr, frame_cptr_sequence, memory_region_bits);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to initialize a vbt instance");
        err = seL4_CNode_Revoke(ut->dest, ut->capPtr, ut->capDepth);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to revoke the original untyped object's cap to delete all frames' capabilities");
            return err;
        }
        allocman_mspace_free(alloc, target_tree, sizeof(vbt_t));
        return err;
    }

    /***
     * Insert the newly created virtual-bitmap-tree into the memory pool.
     * NOTICE:
     *  'frames_window_bits' here is to denote the size of requested memory region that
     *  a virtual-bitmap-tree is managing, which means by using 'frames_window_bits' are
     *  we able to place the tree correctly into the memory pool as there are a lot of
     *  virtual-bitmap-trees with different size in pool at the same time (this is because
     *  freeing and allocating method will affect the number of available frames in a tree
     *  so as to affect the available size of the tree, and the array passed here is sorted
     *  by the available memory size in the tree)
     */
    _capbuddy_linked_list_insert(&alloc->utspace_capbuddy_memory_pool.cell[frames_window_bits], target_tree);

    /***
     * Rather than the virtual-bitmap-tree itself, we need to store its metdata for allocman
     * (the allocator) to do bookkeeping jobs and managing all available & unavailable trees.
     */
    err = _allocman_utspace_append_virtual_bitmap_tree_cookie(alloc, target_tree);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to append newly created virtual-bitmap-tree to allocator");
        return err;
    }
    return seL4_NoError;
}

int allocman_utspace_try_alloc_from_pool(allocman_t *alloc, size_t size_bits,
                                         uintptr_t paddr, bool canBeDev, cspacepath_t *res)
{
    int err = -1;
    if (!alloc->have_utspace) {
        return err;
    }
    /***
     * It should be noted that the metadata of the target memory region
     * can be compressed. We can achieve this by returning 1 cspacepath
     * with its 'capPtr' set to the capability pointer of the first frame
     * of the requested memory region and its 'window' set to the number
     * of frames.
     * 
     *     frames: [1][2][3][4]
     *              ^
     *              |
     *            capPtr = 1 \
     *                        --> target cspacepath_t (compressed)
     *            window = 4 /
     * 
     * So in here, @param: frames_base_cptr = 1 (in the example)
     */
    seL4_CPtr frames_base_cptr;

    if (paddr != ALLOCMAN_NO_PADDR) {
        paddr = paddr & 0xfffff000;
    }

    err = _capbuddy_try_acquire_multiple_frames_at(alloc, paddr, size_bits, &frames_base_cptr);

    /* Failure occurred at our first approch */
    if (err != seL4_NoError) {

        cspacepath_t untyped_original;
        err = allocman_cspace_alloc(alloc, &untyped_original);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to alloc slot for original untyped object.");
            return err;
        }

        /* Why cookies? -> retrieve physical address */
        /* cookie belongs to the internal allocator, we save it here. */
        seL4_CPtr untyped_original_cookie;

        if (paddr != ALLOCMAN_NO_PADDR) {
            untyped_original_cookie =
                allocman_utspace_alloc_at(alloc, 10 + seL4_PageBits, seL4_UntypedObject,
                                          &untyped_original, paddr & 0xffc00000, canBeDev, &err);
        } else {
            untyped_original_cookie =
                allocman_utspace_alloc(alloc, 10 + seL4_PageBits, seL4_UntypedObject,
                                                    &untyped_original, canBeDev, &err);
        }
        if (err != seL4_NoError) {
            allocman_cspace_free(alloc, &untyped_original);
            if (config_set(CONFIG_LIB_ALLOCMAN_DEBUG)) {
                ZF_LOGE("Failed to allocate original untyped object of size: %ld", BIT(10 + seL4_PageBits));
            }
            return err;
        }

        err = allocman_utspace_try_create_virtual_bitmap_tree(alloc, &untyped_original, 10, paddr);
        if (err != seL4_NoError) {
            allocman_utspace_free(alloc, untyped_original_cookie, 10 + seL4_PageBits);
            allocman_cspace_free(alloc, &untyped_original);
            ZF_LOGE("Failed to create new virtual-bitmap-tree from the allocated untyped of 4M size");
            return err;
        }

        /* Now, retry acquiring frames from memory pool */
        err = _capbuddy_try_acquire_multiple_frames_at(alloc, paddr, size_bits, &frames_base_cptr);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to acquire frames from the newly created virtual-bitmap-tree, abort from CapBuddy");
            err = seL4_CNode_Revoke(untyped_original.dest, untyped_original.capPtr, untyped_original.capDepth);
            if (err != seL4_NoError) {
                ZF_LOGE("Failed to revoke the original untyped object's cap to delete all frames' capabilities");
                return err;
            }
            _allocman_utspace_subtract_virtual_bitmap_tree_cookie(alloc, frames_base_cptr);
            allocman_utspace_free(alloc, untyped_original_cookie, 10 + seL4_PageBits);
            allocman_cspace_free(alloc, &untyped_original);
            return err;
        }
    }

    *res = allocman_cspace_make_path(alloc, frames_base_cptr);
    if (size_bits != seL4_PageBits) {
        res->window = BIT(size_bits - seL4_PageBits);
    }
    return 0;
}

void allocman_utspace_try_free_from_pool(allocman_t *alloc, seL4_CPtr cptr, size_t size_bits)
{
#undef TREE_NODE_CPTR_DETERMINE_A_WITHIN_B
#define TREE_NODE_CPTR_DETERMINE_A_WITHIN_B(a,b) \
                                (a >= b && a < b + 1024)
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(alloc->utspace_capbuddy_memory_pool.cookie_rb_tree);
#endif
    node_vbtree *tck;
    /* Try retrieving target virtual-bitmap-tree */
    tck = find_vbt_tree_by_cptr(alloc->utspace_capbuddy_memory_pool.cookie_rb_tree, cptr);
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(TREE_NODE_CPTR_DETERMINE_A_WITHIN_B(cptr, tck->frames_cptr_base));
#endif
    vbt_t *target = tck->target_tree;
    /***
     * Save its current largest available memory region size,
     * in case that this size may change if we are going to do some
     * releasing operations.
     */
    size_t largest_avail = target->largest_avail;
    /***
     * FIXME:
     */
    vbt_update_memory_region_released(target, cptr);

    /* No status change, just return then */
    if (largest_avail == target->largest_avail) {
        /***
         * Only happens when target virtual-bitmap-tree has larger available memory
         * region than the one that requested to be free'd and its largest available
         * memory region was not affected by the one we've just released.
         */
        return;
    }
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety checks */
    assert(largest_avail < target->largest_avail);
    assert(largest_avail <= 10 + seL4_PageBits);
#endif
    /* If the released memory region was from a normal cell */
    if (largest_avail) {
        /* Remove it from its original (normal cell) list */
        _capbuddy_linked_list_remove(&alloc->utspace_capbuddy_memory_pool.cell[largest_avail - seL4_PageBits], target);
    }
    /* Insert it into where it should be */
    _capbuddy_linked_list_insert(&alloc->utspace_capbuddy_memory_pool.cell[target->largest_avail - seL4_PageBits], target);
#undef TREE_NODE_CPTR_DETERMINE_A_WITHIN_B
}

int allocman_cspace_target_object_allocated_from_pool(allocman_t *alloc, seL4_CPtr cptr)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(alloc->have_cspace);
#endif
    int res;
    /* wrapper function for cspace_target_object_allocated_from_pool */
    res = alloc->cspace.pool(alloc, alloc->cspace.cspace, cptr);
    return res;
}

#endif /* CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS */

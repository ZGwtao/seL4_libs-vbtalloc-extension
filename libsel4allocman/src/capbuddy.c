
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

static void _capbuddy_linked_list_insert(vbt_t *tree_linked_list[], vbt_t *target_tree)
{
    /* Safety check */
    assert(target_tree);

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
    assert(TREE_NODE_COMPARE(curr, target_tree, >));
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
    /* Safety check */
    assert(target_tree);
    assert(tree_linked_list);

    vbt_t *head = *tree_linked_list;
    vbt_t *curr = head;

    /* Retrieve target_tree from target list */
    while (curr) {
        if (target_tree == curr) {
            break;
        }
        curr = curr->next;
    }
    /* Check if no error occurs */
    assert(target_tree == curr);
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

static int _capbuddy_try_acquire_multiple_frames(capbuddy_memory_pool_t *pool, size_t real_size, seL4_CPtr *res)
{
    /* Make sure the arg 'real_size' of the requested memory region is legal */
    assert(real_size >= seL4_PageBits);

    /***
     * Try getting the first available virtual-bitmap-tree.
     * The tree must have no less than one piece of available memory region
     * that is large enough to meet the memory request (avail_size > real_size)
     */
    vbt_t *target_tree;

    size_t idx = /* memory pool is sorted by frame number (in bits) of the largest available memory region */
        real_size - seL4_PageBits;  /* 0, 1, 2, 4, ..., 256, 512, 1024 (2^0~10) frames */

    while (idx <= 10) {
        /***
         * As described above, 0 <= idx <= 10, and every unit in memory pool represents
         * a linked-list for the virtual-bitmap-trees with largest available memory region
         * of size 2^idx frames. Since no paddr is required, the query method is FCFS
         */
        target_tree = pool->cell[idx++];
        /***
         * NOTICE:
         *  It's feasible to query a tree with larger available
         *  memory region than the one we requested.
         */
        if (target_tree) {
            /* queried */
            break;
        }
    }
    /* align */
    idx -= 1;

    if (target_tree == NULL) {
        /* Failed to find available tree from CapBuddy's memory pool */
        ZF_LOGV("No available virtual-bitmap-tree has enough memory for %ld memory request", BIT(real_size));
        return -1;
    }

    /***
     * path to the available memory region in a virtual-bitmap-tree
     */
    void *cookie;
    /***
     * Try getting the location of a available memory region from the target_tree.
     * A target_tree may have more than one available memory region to serve the
     * memory requested, so we need to find the first one.
     */
    cookie = vbt_query_avail_memory_region(target_tree, real_size, ALLOCMAN_NO_PADDR);
    if (!cookie) {
        ZF_LOGE("Failed to query cookie in a virtual-bitmap-tree");
        vbt_query_try_cookie_release(cookie);
        return -1;
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

    vbt_query_try_cookie_release(cookie);

    if (target_tree->largest_avail_frame_number_bits == (idx + seL4_PageBits)) {
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
    if (target_tree->largest_avail_frame_number_bits != 0) {
        /***
         * It the updated virtual-bitmap-tree has a different maximum available
         * memory region size, we need to insert it into a new tree linked-list.
         */
        idx = target_tree->largest_avail_frame_number_bits - seL4_PageBits;
        /* do the insertion */
        _capbuddy_linked_list_insert(&pool->cell[idx], target_tree);
        return seL4_NoError;
    }

    vbt_t *tx = pool->useup;
    /* Add target tree into the empty list */
    if (tx) {
        /* FCFS */
        while (tx->next) {
            tx = tx->next;
        }
        tx->next = target_tree;
        /* Released from original list */
        if (target_tree->prev) {
            target_tree->prev->next = target_tree->next;
        }
        if (target_tree->next) {
            target_tree->next->prev = target_tree->prev;
        }
        /* (TAIL) Insert into empty list */
        target_tree->prev = tx;
        target_tree->next = NULL;
        return seL4_NoError;
    }
    /* Add it as the first one */
    pool->useup = target_tree;
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
}

static int _capbuddy_try_acquire_multiple_frames_at(capbuddy_memory_pool_t *pool, uintptr_t paddr, size_t real_size, seL4_CPtr *res)
{
    /* Make sure the arg 'real_size' of the requested memory region is legal */
    assert(real_size >= seL4_PageBits);
    return -1;
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

    vbt_cookie_t *tx;
    /* Allocate space for new cookie's metadata */
    tx = (vbt_cookie_t *)malloc(sizeof(vbt_cookie_t));
    if (!tx) {
        /* Failed to malloc new tree_cookie */
        return -1;
    }
    tx = (vbt_cookie_t *)memset(tx, 0, sizeof(vbt_cookie_t));

    tx->paddr_head = tree->base_physical_address;
    tx->paddr_tail = tree->base_physical_address + (1U << 22); /* 12 page_size + 10 page_num */
    tx->frames_cptr_base = tree->frame_sequence.capPtr;
    tx->target_tree = tree;

    vbt_cookie_t *head;
    /* First virtual-bitmap-tree in capbuddy's memory pool */
    head = alloc->utspace_capbuddy_memory_pool.cookie_linked_list;
    if (!head) {
        alloc->utspace_capbuddy_memory_pool.cookie_linked_list = tx;
        return seL4_NoError;
    }

    /* Retrieve the proper insert point */
    vbt_cookie_t *curr = head;
    while (curr) {
        if (!curr->next) {
            break;
        }
        if (TREE_COOKIE_COMPARE_CPTR(curr->next, tx, >=)) {
            break;
        }
        curr = curr->next;
    }

    /* If at the end of the linked-list */
    if (TREE_COOKIE_COMPARE_CPTR(curr, tx, <)) {
        tx->prev = curr;
        if (curr->next) {
            tx->next = curr->next;
            curr->next->prev = tx;
        }
        curr->next = tx;
        return seL4_NoError;
    }

    assert(TREE_COOKIE_COMPARE_CPTR(curr, tx, >));
    tx->next = curr;
    if (curr->prev) {
        tx->prev = curr->prev;
        curr->prev->next = tx;
    }
    curr->prev = tx;
    /* If it happens to be the head of the linked-list */
    if (TREE_COOKIE_COMPARE_CPTR(head, tx, >)) {
        alloc->utspace_capbuddy_memory_pool.cookie_linked_list = tx;
    }
    return seL4_NoError;
#undef TREE_COOKIE_COMPARE_CPTR
}

int allocman_utspace_try_alloc_from_pool(allocman_t *alloc, seL4_Word type, size_t size_bits,
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
        /* Safety check */
        assert(canBeDev);
        err = _capbuddy_try_acquire_multiple_frames_at(&alloc->utspace_capbuddy_memory_pool, paddr, size_bits, &frames_base_cptr);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to allocate pages at %016lx of size: %d\n", paddr, size_bits);
            /* We fucked it up in here, start debugging now */
            assert(0);
            return err;
        }
        /***
         * Initialize the return value by creating the compressed metadata
         * for frames of the requested memory region.
         */
        *res = allocman_cspace_make_path(alloc, frames_base_cptr);
        if (size_bits != seL4_PageBits) {
            /***
             * @param: size_bits : size in bits of the requested memory region
             * NOTICE:
             *  This's not the size of the memory region managing by the newly
             *  (if any exists) created virtual-bitmap-tree.
             */
            res->window = BIT(size_bits - seL4_PageBits);
        }
        return seL4_NoError;
    }

    /***
     * Try acquiring frames for the requested memory region from CapBuddy,
     * if failed, we should try to construct one new virtual-bitmap tree
     * first, insert it into the memory pool (of CapBuddy), and we'll do
     * it again.
     * TODO:
     *  What it we failed at the second time? Should we try constructing
     *  new trees in an infinate loop? (I don't think that's proper and
     *  that can be the reason to rewrite the code)
     */

    err = _capbuddy_try_acquire_multiple_frames(
                &alloc->utspace_capbuddy_memory_pool, size_bits, &frames_base_cptr);
    /* Failure occurred at our first approch */
    if (err != seL4_NoError) {
        /***
         * constant values to create a new virtual-bitmap-tree (configurable)
         */
        size_t frames_window_bits = 10; /* support 1024 now only */
        size_t frames_window_size = BIT(frames_window_bits);
        size_t memory_region_bits = frames_window_bits + seL4_PageBits;

        /* Allocated metadata before we truely allocating the capability */
        cspacepath_t untyped_original;
        /***
         * Try allocate cspace_path for the original untyped object so
         * as we can access to it under current cspace and move on.
         */
        err = allocman_cspace_alloc(alloc, &untyped_original);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to alloc slot for original untyped object.");
            return err;
        }

        /* Why cookies? -> retrieve physical address */
        /* cookie belongs to the internal allocator, we save it here. */
        seL4_CPtr untyped_original_cookie =
            allocman_utspace_alloc(alloc, memory_region_bits, seL4_UntypedObject,
                                                &untyped_original, canBeDev, &err);
        if (err != seL4_NoError) {
            /* return the bookkeeping value */
            allocman_cspace_free(alloc, &untyped_original);
            if (config_set(CONFIG_LIB_ALLOCMAN_DEBUG)) {
                ZF_LOGE("Failed to allocate original untyped object of size: %ld", BIT(memory_region_bits));
            }
            return err;
        }

        /***
         * Retrieve the physical address of the target memory region
         * (from the orginal untyped object's kernel information)
         */
        uintptr_t untyped_original_paddr =
            allocman_utspace_paddr(alloc, untyped_original_cookie, memory_region_bits);

        vbt_t *target_tree;
        /***
         * FIXME:
         *  What heap manager interface should be called here to store the virtual-bitmaps-
         *  tree's metadata? 'allocman_mspace_alloc' or 'malloc'->sel4muslibcsys? I think
         *  both of them are allocated from the '.bss' section during allocator's bootstrap.
         */
        target_tree = (vbt_t *)malloc(sizeof(vbt_t));
        if (!target_tree) {
            ZF_LOGE("Failed to allocate metadata to bookkeep vbt-tree information");
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            return err;
        }
        target_tree = (vbt_t *)memset(target_tree, 0, sizeof(vbt_t));

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
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            free(target_tree);
            return err;
        }

        err =
            seL4_Untyped_Retype(
                untyped_original.capPtr,    /* '_service' : original untyped object cptr */
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
        /***
         * FIXME:
         *  Will we truely get here? Typically when every resource that needed are provided...
         */
            assert(0);
            /* return err; */
        }

        /***
         * When every thing is ready, let's put the newly created virtual-bitmap-tree into
         * CapBuddy's memory pool, and of course, we need to initialize a metadata for it.
         */
        err = vbt_instance_init(target_tree, untyped_original_paddr, frame_cptr_sequence, memory_region_bits);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to initialize a vbt instance");
            err = seL4_CNode_Revoke(untyped_original.dest, untyped_original.capPtr, untyped_original.capDepth);
            if (err != seL4_NoError) {
                ZF_LOGE("Failed to revoke the original untyped object's cap to delete all frames' capabilities");
                /* Will we get here? */
                assert(0);
            }
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            free(target_tree);
        /* debug */
            while (true);
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

        /* Now, retry acquiring frames from memory pool */
        err = _capbuddy_try_acquire_multiple_frames(&alloc->utspace_capbuddy_memory_pool, size_bits, &frames_base_cptr);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to acquire frames from the newly created virtual-bitmap-tree, abort from CapBuddy");
            /***
             * TODO:
             *   Maybe we should return all of the resources allocated here to the allocator.
             */
            err = seL4_CNode_Revoke(untyped_original.dest, untyped_original.capPtr, untyped_original.capDepth);
            if (err != seL4_NoError) {
                ZF_LOGE("Failed to revoke the original untyped object's cap to delete all frames' capabilities");
                /* Will we get here? */
                assert(0);
            }
            allocman_utspace_free(alloc, untyped_original_cookie, memory_region_bits);
            allocman_cspace_free(alloc, &untyped_original);
            free(target_tree);
            /***
             * FIXME:
             *  allocator bookkeeping metadata for the target_tree needs to be free'd too,
             *  we need to implement this in the future...
             */
            while (true);   /* for debugging purpose, we should turn this on now */
            return err;
        }
    }
    /***
     * Initialize the return value by creating the compressed metadata
     * for frames of the requested memory region.
     */
    *res = allocman_cspace_make_path(alloc, frames_base_cptr);
    if (size_bits != seL4_PageBits) {
        /***
         * @param: size_bits : size in bits of the requested memory region
         * NOTICE:
         *  This's not the size of the memory region managing by the newly
         *  (if any exists) created virtual-bitmap-tree.
         */
        res->window = BIT(size_bits - seL4_PageBits);
    }
    return 0;
}

void allocman_utspace_try_free_from_pool(allocman_t *alloc, seL4_CPtr cptr, size_t size_bits)
{
#undef TREE_NODE_CPTR_DETERMINE_A_WITHIN_B
#define TREE_NODE_CPTR_DETERMINE_A_WITHIN_B(a,b) \
                                (a >= b && a < b + 1024)
    /* Safety check */
    assert(alloc->utspace_capbuddy_memory_pool.cookie_linked_list);

    vbt_cookie_t *tck;
    /* Try retrieving target virtual-bitmap-tree */
    tck = alloc->utspace_capbuddy_memory_pool.cookie_linked_list;
    while (tck) {
        if (TREE_NODE_CPTR_DETERMINE_A_WITHIN_B(cptr, tck->frames_cptr_base)) {
            break;
        }
        tck = tck->next;
    }
    /* Safety check */
    assert(TREE_NODE_CPTR_DETERMINE_A_WITHIN_B(cptr, tck->frames_cptr_base));

    vbt_t *target = tck->target_tree;
    /***
     * Save its current largest available memory region size,
     * in case that this size may change if we are going to do some
     * releasing operations.
     */
    size_t largest_avail_frame_number_bits = target->largest_avail_frame_number_bits;
    /***
     * FIXME:
     */
    vbt_update_memory_region_released(target, cptr);

    /* No status change, just return then */
    if (largest_avail_frame_number_bits == target->largest_avail_frame_number_bits) {
        /***
         * Only happens when target virtual-bitmap-tree has larger available memory
         * region than the one that requested to be free'd and its largest available
         * memory region was not affected by the one we've just released.
         */
        return;
    }
    /* Safety checks */
    assert(largest_avail_frame_number_bits < target->largest_avail_frame_number_bits);
    assert(largest_avail_frame_number_bits <= 10 + seL4_PageBits);

    /* If the released memory region was from a normal cell */
    if (largest_avail_frame_number_bits) {
        /* Remove it from its original (normal cell) list */
        _capbuddy_linked_list_remove(&alloc->utspace_capbuddy_memory_pool.cell[largest_avail_frame_number_bits - seL4_PageBits], target);
        /* Insert it into where it should be */
        _capbuddy_linked_list_insert(&alloc->utspace_capbuddy_memory_pool.cell[target->largest_avail_frame_number_bits - seL4_PageBits], target);
        return;
    }

    /* If it was from a useup cell */
    vbt_t *tx;
    
    /* Try finding it from the useup list */
    tx = alloc->utspace_capbuddy_memory_pool.useup;
    while (tx) {
        if (tx == target) {
            break;
        }
        tx = tx->next;
    }
    assert(tx == target);
    /* Remove it from the original (useup cell) list */
    if (tx->prev) {
        tx->prev->next = tx->next;
    }
    if (tx->next) {
        tx->next->prev = tx->prev;
    }
    /* If we are cutting down the head of the list */
    if (target == alloc->utspace_capbuddy_memory_pool.useup) {
        alloc->utspace_capbuddy_memory_pool.useup = target->next;
    }
    tx->next = NULL;
    tx->prev = NULL;

    /* Insert it into where it should be */
    _capbuddy_linked_list_insert(&alloc->utspace_capbuddy_memory_pool.cell[target->largest_avail_frame_number_bits - seL4_PageBits], target);
#undef TREE_NODE_CPTR_DETERMINE_A_WITHIN_B
}

int allocman_cspace_target_object_allocated_from_pool(allocman_t *alloc, seL4_CPtr cptr)
{
    assert(alloc->have_cspace);
    int res;
    /* wrapper function for cspace_target_object_allocated_from_pool */
    res = alloc->cspace.pool(alloc, alloc->cspace.cspace, cptr);
    return res;
}

#endif /* CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS */

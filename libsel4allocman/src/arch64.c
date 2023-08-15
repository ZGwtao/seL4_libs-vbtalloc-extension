
#include <allocman/capbuddy.h>

#define VBT_NO_PADDR 1

#if CONFIG_WORD_SIZE == 64

static inline int
    __bitmap_retrieve_descendants_num_between_levels(int l1, int l2)
{
    return 1 << (l1 - l2);
}

static size_t __bitmap_update_propagate_descendants(int x)
{
    size_t r = 0;

    int l = BITMAP_GET_LEVEL(x);
    /***
     * =l denotes current level
     * <l denotes ancestor level
     * >l denotes descendant level
     */
    for (int i = l + 1; i <= BITMAP_DEPTH; ++i)
    {
        for (int j1 = 0,
                 j2 = 1 << (i - l); j1 < j2; ++j1)
        {
            r += VBT_INDEX_BIT(x * j2 + j1);
        }
    }
    return r;
}

static void __bitmap_update_memory_region_released(void *data, int mr_idx)
{
    assert(data); /* Safety check */
    arch64_bitmap_t *bitmap = (arch64_bitmap_t*)data;

    bitmap->map |= __bitmap_update_propagate_descendants(mr_idx);
    bitmap->map |= VBT_INDEX_BIT(mr_idx);
    
    int buddy = mr_idx % 2 ? mr_idx - 1 : mr_idx + 1;
    if (!VBT_AND(bitmap->map, VBT_INDEX_BIT(buddy))) {
        return;
    }

    int idx = mr_idx >> 1;
    size_t dtc = VBT_INDEX_BIT(idx);
    while(idx) {
        bitmap->map |= dtc;
        buddy = idx % 2 ? idx - 1 : idx + 1;
        if (!VBT_AND(bitmap->map, VBT_INDEX_BIT(buddy))) {
            return;
        }
        idx >>= 1;
        if (idx == 0) break;
        dtc = VBT_INDEX_BIT(idx);
    }
}

static void __bitmap_update_memory_region_acquired(void *data, int mr_idx)
{
    assert(data); /* Safety check */

    arch64_bitmap_t *bitmap = (arch64_bitmap_t*)data;
    /* recursively update ancestors' status */
    int idx = mr_idx >> 1;
    size_t dtc = VBT_INDEX_BIT(idx);
/* ancestors */
    while(idx) {
        if (!VBT_AND(dtc, bitmap->map)) {
            break;
        }
        bitmap->map -= dtc;
        idx >>= 1;
        dtc = VBT_INDEX_BIT(idx);
    }
/* descendants */
    bitmap->map &= ~__bitmap_update_propagate_descendants(mr_idx);
/* value itself */
    bitmap->map &= ~(VBT_INDEX_BIT(mr_idx));
}

static void __two_level_bitmap_try_query_avail_memory_region_at(void *data, size_t sidx, /* frame index */
                                                                size_t fn, void *res, int *err)
{
#undef MAPSIZE_FRAME
#define MAPSIZE_FRAME 32
    assert(fn == 0);

    /* Safety check */
    assert(data);
    assert(res);
    assert(err);

    address_cell_t *cell = (address_cell_t *)res;
    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t *)data;

    *err = -1;

    arch64_bitmap_t *l1 = &target->l1; /* original level-1 bitmap */
    arch64_bitmap_t *l2 = NULL; /* Potential level-2 bitmap */

    if (fn > BITMAP_LEVEL) {
        /* Not implemented yet. */
        return;
    }

    if (!VBT_AND(l1->map, VBT_INDEX_BIT(32 + (sidx / MAPSIZE_FRAME)))) {
        /* Target frame is currently unavailable */
        return;
    }

    /* Target level-2 bitmap to be queired */
    l2 = &target->l2[sidx / MAPSIZE_FRAME];

    if (!VBT_AND(l2->map, VBT_INDEX_BIT(32 + (sidx % MAPSIZE_FRAME)))) {
        /* Target frame is currently unavailable */
        return;
    }

    *err = seL4_NoError;

    cell->i1 = 32 + (sidx / MAPSIZE_FRAME);
    cell->i2 = 32 + (sidx % MAPSIZE_FRAME);

#undef MAPSIZE_FRAME
}

static void __two_level_bitmap_try_query_avail_memory_region(void *data, size_t fn, void *res, int *err)
{
    /* Safety check */
    assert(data);
    assert(res);
    assert(err);

    address_cell_t *cell = (address_cell_t *)res;
    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t *)data;

    /* default error status */
    *err = -1;

    arch64_bitmap_t *l2 = NULL;
    arch64_bitmap_t *l1 = &target->l1;

    if (fn > BITMAP_LEVEL) {
        int base = L1IDX(fn);
        int avail = CLZL(MASK((BITMAP_SIZE) - base) & (l1->map));
        if (avail < base * 2) {
            /* available memory region is retrieved */
            *err = seL4_NoError;
            cell->i1 = avail;
        }
        return;
    }

    for (int i = 32; i < 64 && !(cell->i2); ++i) {
        if (!VBT_AND(l1->map, VBT_INDEX_BIT(i))) {
            continue;
        }
        l2 = &target->l2[BITMAP_SUB_OFFSET(i)];

        int base = L2IDX(fn);
        int avail = CLZL(MASK((BITMAP_SIZE) - base) & (l2->map));
        
        if (avail < base * 2) {
            /* available memory region is retrieved */
            *err = seL4_NoError;
            /* two-level (size < 256k) */
            cell->i1 = i;
            cell->i2 = avail;
        }
    }
}

static size_t __two_level_bitmap_update_largest(void *data)
{
    /* Safety check */
    assert(data);

    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t *)data;

    arch64_bitmap_t *l1 = &target->l1;

    size_t rv;  /* return value */

    int mr_i1 = CLZL(l1->map);
    /***
     * If this is a useup tree, just return zero since there are no
     * available memory region in it.
     */
    if (mr_i1 == 64) {
        return 0;
    }
    /***
     * Current largest available memory region is larger than 128k.
     * So we should prepare the number of frames in bits as well as
     * the frame size in bits and add them up to return
     */
    if (mr_i1 < 32) {
        /* 18 ~ 22 */
        rv = ((BITMAP_DEPTH) - BITMAP_GET_LEVEL(mr_i1)) + ((BITMAP_LEVEL) + (seL4_PageBits));
        assert(rv >= 18); /* pow(2,18) = 256k */
        return rv;
    }

    int tx;
    int ux = 64; /* leading zeros number will at most be 63 because last 4k is 63 */
    int mr_i1_top = 64; /* index of the last bit of l2 bitmap in l1 is 63 */

    for (int i = mr_i1; i < mr_i1_top; ++i) {
        /***
         * Query every l2 bitmap to see what's the largest available
         * memory region size among them all (at most = 128k)
         */
        if (VBT_AND(l1->map, VBT_INDEX_BIT(i))) {
            /***
             * If target l2 bitmap is not useup, try retrieving the
             * largest available memory region size from this l2 bitmap
             */
            tx = CLZL(MASK(63) & target->l2[BITMAP_SUB_OFFSET(i)].map);
            /***
             * If one new largest available memory region size is retrieved,
             * update it and try to return. leading zeros number is inversely
             * proportional to largest available memory region size
             */
            if (tx < ux) {
                ux = tx;
            }
            if (ux == 1) {  /* 128k retrieved */
                break;
            }
        }
    }
    /* 12 ~ 17 */
    rv = ((BITMAP_DEPTH) - BITMAP_GET_LEVEL(ux)) + (seL4_PageBits);
    assert(rv >= 12);
    return rv;
}

static void __two_level_bitmap_update_memory_region_acquired(void *data, const void *cookie)
{
    assert(data);
    assert(cookie);

    address_cell_t *path = (address_cell_t *)cookie;
    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t*)data;

    arch64_bitmap_t *l1 = &target->l1;
    arch64_bitmap_t *l2 = NULL;

#undef CHECK_REQUEST_L1_BASED /* > 128k memory requests */
#define CHECK_REQUEST_L1_BASED(cell) (cell->i2 == 0)
    /***
     * Requested memory region is > 128k in size, so we need to update its
     * l1 bitmap first, and propagate the update to the potentially affected
     * l2 bitmaps then.
     */
    if (CHECK_REQUEST_L1_BASED(path)) {
        /* Update l1 bitmap first */
        __bitmap_update_memory_region_acquired(l1, path->i1);
        
        int window = __bitmap_retrieve_descendants_num_between_levels(BITMAP_DEPTH, BITMAP_GET_LEVEL(path->i1));
        
        int sti = BITMAP_SUB_OFFSET(window * path->i1);
        
        for (int i = sti; i < sti + window; ++i) {
            if (!VBT_AND(l1->map, VBT_INDEX_BIT(i))) {
                target->l2[i].map = 0ul;
            }
        }
        return;
    }

    l2 = &target->l2[BITMAP_SUB_OFFSET(path->i1)];
    
    __bitmap_update_memory_region_acquired(l2, path->i2);
    
    int idx = path->i1;
    size_t dtc = VBT_INDEX_BIT(idx);
    while(idx) {
        if (!VBT_AND(dtc, l1->map)) {
            break;
        }
        l1->map -= dtc;
        idx >>= 1;
        dtc = VBT_INDEX_BIT(idx);
    }
    if (l2->map != 0) {
        l1->map += (VBT_INDEX_BIT(path->i1));
    }
#undef CHECK_REQUEST_L1_BASED
}

static void __two_level_bitmap_update_memory_region_released(void *data, const void *cookie)
{
    assert(data);
    assert(cookie);

    address_cell_t *path = (address_cell_t *)cookie;
    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t*)data;

    arch64_bitmap_t *l1 = &target->l1;
    arch64_bitmap_t *l2 = NULL;

#undef CHECK_REQUEST_L1_BASED /* > 128k memory requests */
#define CHECK_REQUEST_L1_BASED(cell) (cell->i2 == 0)

    if (CHECK_REQUEST_L1_BASED(path)) {

        __bitmap_update_memory_region_released(l1, path->i1);

        int window = __bitmap_retrieve_descendants_num_between_levels(BITMAP_DEPTH, BITMAP_GET_LEVEL(path->i1));
        int sti = BITMAP_SUB_OFFSET(window * path->i1);
        
        for (int i = sti; i < sti + window; ++i) {
            if (!VBT_AND(l1->map, VBT_INDEX_BIT(i))) {
                target->l2[i].map = MASK(63) & (uint64_t)-1;
            }
        }
        return;
    }

    l2 = &target->l2[BITMAP_SUB_OFFSET(path->i1)];

    __bitmap_update_memory_region_released(l2, path->i2);
/***
 * FIXME:
 *  later code can be replaced by '__bitmap_update_memory_region_released'
 */

    if (l2->map != MASK(63)) {
        return;
    }

    /* i1 denotes the updated the l2 bitmap here */
    int l2_target = path->i1;
    /* Retrieve target_l2's buddy bitmap */
    int l2_buddy =
            l2_target % 2 ? l2_target - 1 : l2_target + 1;

    /***
     * Buddy l2 bitmap has different status with target l2, which means
     * target l2 now being an totally available bitmap (all 128k) while
     * Buddy l2 now still is partially unavailable. 
     */
    if (l2->map != target->l2[BITMAP_SUB_OFFSET(l2_buddy)].map) {
        /***
         * No need to modify the two_level_bitmap's status, just return
         */
        return;
    }

    l1->map |= (VBT_INDEX_BIT(l2_target));
    l1->map |= (VBT_INDEX_BIT(l2_buddy));

    int buddy;
    int idx = path->i1 >> 1;
    size_t dtc = VBT_INDEX_BIT(idx);
    while(idx) {
        l1->map |= dtc;
        buddy = idx % 2 ? idx - 1 : idx + 1;
        if (!VBT_AND(l1->map, VBT_INDEX_BIT(buddy))) {
            break;
        }
        idx >>= 1;
        if (idx == 0) break;
        dtc = VBT_INDEX_BIT(idx);
    }           
#undef CHECK_REQUEST_L1_BASED
}

static void __two_level_bitmap_init(void *target_tree)
{
    /* Safety check */
    assert(target_tree);

    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t *)target_tree;
    /***
     * Initialize it with 1024 frames, so the original entry
     * of the virtual-bitmap-tree is (1,0) in two-level tree
     * querying structure, this is because i1 = 1 means
     * 4M (1024 pages) i2 = 0 means no need to query sub
     * level's memory region status.
     */
    target->largest_cell.i1 = 1;
    target->largest_cell.i2 = 0;
    /***
     * Initialize 256k ~ 4M virtual memory regions' status
     * 
     * In one bitmap:
     *  [0] -> reserved
     *  [1] -> 4M, [2~3] -> 2M, [4~7] -> 1M, [8~15] -> 512k
     *  [16~31] -> 256k, [32~64] -> status of 32 sub-level bitmaps
     */
    target->l1.map = 0x7fffffffffffffff;
    /***
     * There are at most 32 sub-level bitmaps to record the
     * status of all of the virtual memory regions with their
     * sizes smaller than 256k
     * 
     * In one bitmap:
     *  [0] -> reserved
     *  [1] -> 128k, [2~3] -> 64k, [4~7] -> 32k, [8~15] -> 16k
     *  [16~31] -> 8k, [32~63] -> 4k
     */
    for (int i = 0; i < 32; ++i) {
        /***
         * Initialize <=128k virtual memory regions' status
         */
        target->l2[i].map = 0x7fffffffffffffff;
    }
}

static seL4_CPtr __two_level_bitmap_frame_offset_operator(const void *cookie)
{
    assert(cookie);
    address_cell_t *p = (address_cell_t *)cookie;

    int size, base, ofs;

    if (p->i2 == 0)
    {
        size = BITMAP_DEPTH - BITMAP_GET_LEVEL(p->i1) + BITMAP_LEVEL;
        base = BIT(BITMAP_GET_LEVEL(p->i1) - 1);
        ofs = p->i1 - base;

        return ofs * BIT(size);
    }

    size = BITMAP_DEPTH - BITMAP_GET_LEVEL(p->i2);
    base = BIT(BITMAP_GET_LEVEL(p->i2) - 1);
    ofs = p->i2 - base;

    return ofs * BIT(size) + (p->i1 - 32) * 32;
}

void arch64_vbt_make_interface(void *data)
{
    assert(data); /* Safety check */
    vbt_t *target = (vbt_t *)data;
/* target->arch_data interfaces */
    target->arch_data->arch_init = __two_level_bitmap_init;
/* target interfaces */
    target->arch_update_largest = __two_level_bitmap_update_largest;
/***
 * TODO: instantiate this in the near future.
 */
    target->arch_query_avail_mr_at = __two_level_bitmap_try_query_avail_memory_region_at;
    target->arch_query_avail_mr = __two_level_bitmap_try_query_avail_memory_region;
    target->arch_acquire_mr = __two_level_bitmap_update_memory_region_acquired;
    target->arch_release_mr = __two_level_bitmap_update_memory_region_released;
    target->arch_frame_offset = __two_level_bitmap_frame_offset_operator;
}

#endif /* CONFIG_WORD_SIZE == 64 */
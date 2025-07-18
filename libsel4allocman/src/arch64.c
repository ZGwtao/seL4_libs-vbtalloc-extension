
#include <allocman/capbuddy.h>

#define VBT_NO_PADDR 1

#if CONFIG_WORD_SIZE == 64

static inline int
    __bitmap_retrieve_descendants_num_between_levels(int l1, int l2)
{
    return 1 << (l1 - l2);
}

#if 1
static size_t __bitmap_update_propagate_descendants(int x)
{
    size_t r = 0;

    int l = 64 - __builtin_clzl(x);
    /***
     * =l denotes current level
     * <l denotes ancestor level
     * >l denotes descendant level
     */
    for (int i = l + 1; i <= 6; ++i) {
        for (int j = 0; j < 1 << (i - l); ++j) {
            r |= (1ULL << (63 - ((x << (i - l)) + j)));
        }
    }
    return r;
}
#else
static inline size_t __bitmap_update_propagate_descendants(int x)
{
    size_t r = 0;

    if (x == 0) return r;  // avoid undefined behavior in __builtin_clz

    // Compute the level of x based on leading zero count
    int l = 64 - __builtin_clzl((unsigned long)x);

    for (int i = l + 1; i <= 6; ++i)
    {
        int shift = i - l;
        int j2 = 1 << shift;
        int base = x << shift;  // equivalent to x * j2, faster

        for (int j1 = 0; j1 < j2; ++j1)
        {
            int bit_index = 63 - (base + j1);  // 63 = 64 - 1
            r |= 1ULL << bit_index;
        }
    }

    return r;
}
#endif

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
    while(idx) {
        bitmap->map |= (1ULL << (BITMAP_SIZE - 1 - idx));
        buddy = idx % 2 ? idx - 1 : idx + 1;
        if (!((bitmap->map >> (BITMAP_SIZE - 1 - buddy)) & 1)) {
            return;
        }
        idx >>= 1;
    }
}

static void __bitmap_update_memory_region_acquired(void *data, int mr_idx)
{
    assert(data); /* Safety check */

    arch64_bitmap_t *bitmap = (arch64_bitmap_t*)data;
    /* recursively update ancestors' status */
    int idx = mr_idx >> 1;
/* ancestors */
    while(idx) {
        if (!((bitmap->map >> (BITMAP_SIZE - 1 - idx)) & 1)) {
            break;
        }
        bitmap->map &= ~(1ULL << (BITMAP_SIZE - 1 - idx));
        idx >>= 1;
    }
/* descendants */
    bitmap->map &= ~__bitmap_update_propagate_descendants(mr_idx);
/* value itself */
    bitmap->map &= ~(1ULL << (BITMAP_SIZE - 1 - mr_idx));
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

    if (!((l1->map >> (BITMAP_SIZE - 1 - (32 + (sidx / MAPSIZE_FRAME)))) & 1)) {
        /* Target frame is currently unavailable */
        return;
    }

    /* Target level-2 bitmap to be queired */
    l2 = &target->l2[sidx / MAPSIZE_FRAME];

    if (!((l2->map >> (BITMAP_SIZE - 1 - (32 + (sidx % MAPSIZE_FRAME)))) & 1)) {
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
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(data);
    assert(res);
    assert(err);
#endif
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
    /* check available level 2 bitmap */
    size_t map_l1;
    size_t avail_index;

    /* this optimisation can boost up the anonymous request by 400 cycles */
    map_l1 = l1->map;
    /* replace for loop with FFSL -> no need to consider the zeros */
    while (!cell->i2) {
        avail_index = 64 - FFSL(map_l1);
        /* XXX: possible? (looks like prefecher takes BAD care of this) */
        //if (avail_index < 32) {
        //    break;
        //}
        l2 = &target->l2[BITMAP_SUB_OFFSET(avail_index)];

        int base = L2IDX(fn);
        int avail = CLZL(MASK((BITMAP_SIZE) - base) & (l2->map));
        
        if (avail < base * 2) {
            /* available memory region is retrieved */
            *err = seL4_NoError;
            /* two-level (size < 256k) */
            cell->i1 = avail_index;
            cell->i2 = avail;
        } else {
            // FIXME
            map_l1 &= ~(1ULL << (FFSL(map_l1) - 1));
        }
    }
}

static size_t __two_level_bitmap_update_largest(void *data)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(data);
#endif
    arch64_two_level_bitmap_t *target = (arch64_two_level_bitmap_t *)data;

    arch64_bitmap_t *l1 = &target->l1;

    size_t rv;  /* return value */

    int avail_index = CLZL(l1->map);
    /***
     * If this is a useup tree, just return zero since there are no
     * available memory region in it.
     */
     // For some reason, not work for x86_64?
    if (!target->l1.map) {
        return 0;
    }
    /***
     * Current largest available memory region is larger than 128k.
     * So we should prepare the number of frames in bits as well as
     * the frame size in bits and add them up to return
     */
    if (avail_index < 32) {
        /* 18 ~ 22 */
        rv = ((BITMAP_DEPTH) - BITMAP_GET_LEVEL(avail_index)) + ((BITMAP_LEVEL) + (seL4_PageBits));
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
        assert(rv >= 18); /* pow(2,18) = 256k */
#endif
        return rv;
    }

    int tx;
    int ux = 64; /* leading zeros number will at most be 63 because last 4k is 63 */
    size_t map_l1 = l1->map;
    /* ux = 1(128K), 2~3(64K), ... 32~63(4K) */
    while (map_l1) {
        avail_index = 64 - FFSL(map_l1);
        if (avail_index < 32) break;
        /***
         * Query every l2 bitmap to see what's the largest available
         * memory region size among them all (at most = 128k)
         */
        tx = CLZL(MASK(63) & target->l2[BITMAP_SUB_OFFSET(avail_index)].map);
        /* smaller the index is, larger the block is */
        ux = tx < ux ? tx: ux;
        /* no larger granularity for 128K */
        if (ux == 1) {
            break;
        }
        map_l1 &= ~(1ULL << (FFSL(map_l1) - 1));
    }
    /* 12 ~ 17 */
    rv = ((BITMAP_DEPTH) - BITMAP_GET_LEVEL(ux)) + (seL4_PageBits);
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(rv >= 12);
#endif
    return rv;
}

static void __two_level_bitmap_update_memory_region_acquired(void *data, const void *cookie)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(data);
    assert(cookie);
#endif
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
            if (!((l1->map >> (BITMAP_SIZE - 1 - i)) & 1)) {
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
        if (!((l1->map >> (BITMAP_SIZE - 1 - idx)) & 1)) {
            break;
        }
        l1->map &= ~(1ULL << (BITMAP_SIZE - 1 - idx));
        idx >>= 1;
    }
    if (l2->map != 0) {
        l1->map += (VBT_INDEX_BIT(path->i1));
    }
#undef CHECK_REQUEST_L1_BASED
}

static void __two_level_bitmap_update_memory_region_released(void *data, const void *cookie)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(data);
    assert(cookie);
#endif
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
            if (!((l1->map >> (BITMAP_SIZE - 1 - i)) & 1)) {
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
    while(idx) {
        l1->map |= (1ULL << (BITMAP_SIZE - 1 - idx));
        buddy = idx % 2 ? idx - 1 : idx + 1;
        if (!((l1->map >> (BITMAP_SIZE - 1 - buddy)) & 1)) {
            break;
        }
        idx >>= 1;
    }           
#undef CHECK_REQUEST_L1_BASED
}

static void __two_level_bitmap_init(void *target_tree)
{
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    /* Safety check */
    assert(target_tree);
#endif
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
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(cookie);
#endif
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
#ifdef CONFIG_LIB_ALLOCMAN_DEBUG
    assert(data); /* Safety check */
#endif
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
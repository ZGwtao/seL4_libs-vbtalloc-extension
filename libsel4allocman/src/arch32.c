
#include <allocman/capbuddy.h>
#include <kernel/gen_config.h>

#define VBT_NO_PADDR 1

#if CONFIG_WORD_SIZE == 32

#define MAPSIZE CONFIG_WORD_SIZE

#define ARCH_BIT(n) (1U << n)
#define SET_BIT(map, n) (map |= (1U << (MAPSIZE - (n + 1))))
#define CLEAR_BIT(map, n) (map &= ~(1U << (MAPSIZE - (n + 1))))
#define CHECK_ZERO(map, n) ((map & (1U << (MAPSIZE - (n + 1)))) == 0)

static void __single_level_bitmap_query_avail_mr_at(void *data, size_t sidx, size_t fn, void *res, int *err)
{
    /***
     * TODO: multiple memory region acquiring & freeing support
     * 
     * For querying contiguous multiple frames of requested memory region,
     * it's not enough to have one acquiring method, this is becasue the
     * requested frames may overlay with multiple virtual memory regions
     * of their total size, e.g.
     *                          R   <--- root
     *                        /   \
     *                      X1     X2   <-- virtual memory regions (same size)
     *                     /  \   /  \
     *                    X3 [X4 X5] X6
     *                         ^-------- the one we want (overlay with 1,2)
     * 
     * Of course, we can implement different policies for this, but now it's
     * unnecessary.
     */
    assert(fn == 0);

    /* Safety check */
    assert(data);
    assert(res);
    assert(err);

    address_index_t *fx = (address_index_t *)res;
    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;

    /* default error status */
    *err = -1;

    if (!CHECK_ZERO(target->bma[(1024 + sidx) / MAPSIZE].map, (1024 + sidx) % MAPSIZE)) {
        /***
         * Destination frame is not allocated yet, return positive result and initialize
         * the result cookie by setting its value to the frame index (sidx) + 1024, this
         * is just because cookie should be the global index of all virtual memory regions
         * in a virtual-bitmap-tree.
         */
        *err = seL4_NoError;
        /***
         * Initialize it, 1024 is the start of all frames, while sidx is the offset of
         * the target frame we want
         */
        fx->idx = 1024 + sidx;
    }
}

static void __single_level_bitmap_query_avail_mr(void *data, size_t fn, void *res, int *err)
{
    /* Safety check */
    assert(data);
    assert(res);
    assert(err);

    address_index_t *fx = (address_index_t *)res;
    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;

    /* default error status */
    *err = -1;

    /* base number */
    int b1 = BIT(10 - fn);
    int b2 = BIT(10 - (fn - 1));
    /* query number */
    int q1 = b1 / MAPSIZE;
    int q2 = b2 / MAPSIZE;

    if (q1 == 0) {
        /***
         * Size of requested memory region is (256k <= mr <= 4M)
         * So we have to handled the included very first reserved bit.
         */
        int r = CLZ(target->bma[0].map); // query result
        if (r < b1) {
            *err = seL4_NoError;
            for (int i = b1; i < b2; ++i) {
                if (!CHECK_ZERO(target->bma[0].map, i)) {
                    fx->idx = i;
                    break;
                }
            }
        } else if (r < b2 && r >= b1) {
            /***
             * If valid query result is found, set cookie value to its result and return,
             * otherwise do nothing as the cookie has been 'memset' before the querying
             * procedure started.
             */
            *err = seL4_NoError;
            fx->idx = r;
        }
        return;
    }
    /***
     * requested memory region is smaller than 256k
     * (4k <= mr <= 128k)
     */
    int t; // query value
    int r = b1; // query result
    for (int i = q1; i < q2; ++i) {
        t = CLZ(target->bma[i].map);
        if (t < MAPSIZE) {
            *err = seL4_NoError;
            fx->idx = r + t; // update cookie
            break;
        }
        r += MAPSIZE;
    }
    /* Don't update fx(cookie) with r here */
}

static size_t __single_level_bitmap_refresh_largest_avail_mr(void *data)
{
    /* Safety check */
    assert(data);

    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;

    int r;
    r = CLZ(target->bma[0].map);
    if (r < MAPSIZE) {
        return seL4_PageBits + 10 - (MAPSIZE - (CLZ(r) + 1)); // 10 denotes 2^10 = 1024
    }
    /* smaller than 256k */
    int i = 1;
    while (i < 64) {
        if (CLZ(target->bma[i].map) < MAPSIZE) {
            break;
        }
        i += 1;
    }
    if (i == 64) {
        return 0;
    }
    return seL4_PageBits + 6 - (MAPSIZE - CLZ(i));
}

static void __single_level_bitmap_update_mr_acquired(void *data, const void *cookie)
{
    assert(data);
    assert(cookie);

    address_index_t *fx = (address_index_t *)cookie;
    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;
    /* original value */
    int tx = fx->idx;
    /* iteration variables */
    int tc = tx;
    int base = tx / MAPSIZE;
    int offset = tx % MAPSIZE;
    /* Ensure it hasn't been free yet */
    assert(!CHECK_ZERO(target->bma[base].map, offset));
    /* update ancestors & self */
    while (tc > 0) {
        if (CHECK_ZERO(target->bma[base].map, offset)) {
            break;
        }
        CLEAR_BIT(target->bma[base].map, offset);
        tc >>= 1;
        base = tc / MAPSIZE;
        offset = tc % MAPSIZE;
    }
    /* update descendants */
    int kx = 1;
    tc = tx << 1;
    while (tc < 2048)
    {
        for (int i = tc; i < tc + ARCH_BIT(kx); ++i)
        {
            CLEAR_BIT(target->bma[i / MAPSIZE].map, (i % MAPSIZE));
        }
        tc <<= 1;
        kx += 1;
    }
#if 0
    for (int i = 0; i < 64; ++i) {
        if (i % 8 == 0) {
            printf("\n");
        }
        printf("%08x ", target->bma[i].map);
    }
    printf("\n");
#endif
}

static void __single_level_bitmap_update_mr_released(void *data, const void *cookie)
{
    /* Safety check */
    assert(data);
    assert(cookie);

    address_index_t *fx = (address_index_t *)cookie;
    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;
    /* original value */
    int tx = fx->idx;
#if 0
    printf("\n%d\n", tx);
    for (int i = 0; i < 64; ++i) {
        if (i % 8 == 0) printf("\n");
        printf("[%2d]: %08x ", i, target->bma[i].map);
    }
    printf("\n");
#endif
    if (tx == 1) {
        for (int i = 1; i < 64; ++i) {
            target->bma[i].map = 0xffffffff;
        }
        target->bma[0].map = 0x7fffffff;
        return;
    }
    /* iteration variables */
    int tc = tx;
    int base = tx / MAPSIZE;
    int offset = tx % MAPSIZE;
    /* Ensure it has been free already */
    assert(CHECK_ZERO(target->bma[base].map, offset));

    int kx = 0;
    /* descendants & self */
    while (tc < 2048) {
        for (int i = tc; i < tc + ARCH_BIT(kx); ++i) {
            SET_BIT(target->bma[i / MAPSIZE].map, (i % MAPSIZE));
        }
        tc <<= 1;
        kx += 1;
    }
    /* ancestors */
    tc = tx;
    int bx = tc % 2 ? tc - 1 : tc + 1; // buddy index
    while (!CHECK_ZERO(target->bma[bx / MAPSIZE].map, (bx % MAPSIZE))) {
        tc >>= 1;
        SET_BIT(target->bma[tc / MAPSIZE].map, (tc % MAPSIZE));
        if (tc == 1) {
            break;
        }
        bx = tc % 2 ? tc - 1 : tc + 1;
    }
}

static void __single_level_bitmap_init(void *data)
{
    /* Safety check */
    assert(data);

    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;
    /***
     * Initialize the whole bitmap structure in single-level bitmap of virtual-
     * bitmap-tree. We use true to denote a memory region is available (to be
     * required, so as its descendants)
     */
    for (int i = 1; i < 64; ++i) {
        target->bma[i].map = 0xffffffff;
    }
    /***
     * The very first bit among all bitmaps is reserved, while not like two-level
     * bitmaps, only 1 bit is reserved in single-level bitmap structure.
     */
    target->bma[0].map = 0x7fffffff;
}

static seL4_CPtr __single_level_bitmap_offset_operator(const void *cookie)
{
    /* Safety check */
    assert(cookie);
    address_index_t *p = (address_index_t *)cookie;
    /* no more than 2048 */
    int idx = p->idx;
    if (idx >= 2048) {
        ZF_LOGE("Invalid memory region cookie: overwhelm index");
        assert(0);
    }
    while (idx < 1024) {
        idx <<= 1;
    }
    return (seL4_CPtr)(idx - 1024);
}

void arch32_vbt_make_interface(void *data)
{
    assert(data); /* Safety check */
    vbt_t *target = (vbt_t *)data;
/* target->arch_data interfaces */
    target->arch_data->arch_init = __single_level_bitmap_init;
/* target interfaces */
    target->arch_update_largest = __single_level_bitmap_refresh_largest_avail_mr;
    target->arch_query_avail_mr_at = __single_level_bitmap_query_avail_mr_at;
    target->arch_query_avail_mr = __single_level_bitmap_query_avail_mr;
    target->arch_acquire_mr = __single_level_bitmap_update_mr_acquired;
    target->arch_release_mr = __single_level_bitmap_update_mr_released;
    target->arch_frame_offset = __single_level_bitmap_offset_operator;
}
#endif /* CONFIG_WORD_SIZE == 64 */
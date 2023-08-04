
#include <allocman/capbuddy.h>

#define VBT_NO_PADDR 1

#define MAPSIZE CONFIG_WORD_SIZE

#define ARCH_BIT(n) (1U << n)
#define SET_BIT(map, n) (map |= (1U << (MAPSIZE - (n + 1))))
#define CLEAR_BIT(map, n) (map &= ~(1U << (MAPSIZE - (n + 1))))
#define CHECK_ZERO(map, n) ((map & (1U << (MAPSIZE - (n + 1)))) == 0)

static void __single_level_bitmap_query_avail_mr(void *data, size_t fn, void *res)
{
    /* Safety check */
    assert(data);
    assert(res);

    address_index_t *fx = (address_index_t *)res;
    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;

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
        if (r < b2 && r >= b1) {
            /***
             * If valid query result is found, set cookie value to its result and return,
             * otherwise do nothing as the cookie has been 'memset' before the querying
             * procedure started.
             */
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
    if (r < 64) {
        return seL4_PageBits + 10 - (MAPSIZE - (CLZ(r) + 1)); // 10 denotes 2^10 = 1024
    }
    /* smaller than 256k */
    int i = 1;
    while (i < 64) {
        if (CLZ(target->bma[i].map) < 64) {
            break;
        }
        i += 1;
    }
    return seL4_PageBits + 6 - (MAPSIZE - CLZ(i));
}

static void __single_level_bitmap_update_mr_acquired(void *data, const void *cookie)
{
    assert(data);
    assert(cookie);

    seL4_Word *fx = (seL4_Word *)cookie;
    arch32_single_level_bitmap_t *target = (arch32_single_level_bitmap_t *)data;
    /* original value */
    int tx = *fx;
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

}

void arch32_vbt_make_interface(void *data)
{
    assert(data); /* Safety check */
    vbt_t *target = (vbt_t *)data;
/* target->arch_data interfaces */
    target->arch_data->arch_init = __single_level_bitmap_init;
/* target interfaces */
    target->arch_update_largest = __single_level_bitmap_refresh_largest_avail_mr;
    target->arch_query_avail_mr = __single_level_bitmap_query_avail_mr;
    target->arch_acquire_mr = __single_level_bitmap_update_mr_acquired;
    target->arch_release_mr = __single_level_bitmap_update_mr_released;
    target->arch_frame_offset = __single_level_bitmap_offset_operator;
}


#include <allocman/capbuddy.h>

#define VBT_NO_PADDR 1

#define MAPSIZE CONFIG_WORD_SIZE

static void __single_level_bitmap_query_avail_mr(void *data, size_t fn, void *res)
{
    /* Safety check */
    assert(data);
    assert(res);

    seL4_Word *fx = (seL4_Word *)res;
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
            *fx = r;
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
            *fx = r + t; // update cookie
            break;
        }
        r += MAPSIZE;
    }
    /* Don't update fx(cookie) with r here */
}

static size_t __single_level_bitmap_refresh_largest_avail_mr(void *data)
{

}

static void __single_level_bitmap_update_mr_acquired(void *data, const void *cookie)
{

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

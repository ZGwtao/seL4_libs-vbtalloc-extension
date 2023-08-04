
#include <allocman/capbuddy.h>

#define VBT_NO_PADDR 1

static void __single_level_bitmap_query_avail_mr(void *data, size_t fn, void *res)
{

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

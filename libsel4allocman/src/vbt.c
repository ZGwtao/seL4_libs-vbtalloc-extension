
#include <allocman/vbt.h>
#include <assert.h>
#include <string.h>
#include <utils/util.h>

/***
 * Initialize a virtual-bitmap-tree.
 * 
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param paddr : physical address of the requested memory region
 * @param fcs : frames cptr sequence (compressed in one 'cspacepath_t' variable)
 * @param origin_size_bits : default available memory region size of the tree, (should be 10+12)
 */
int vbt_instance_init(vbt_t *data, uintptr_t paddr, cspacepath_t fcs, size_t origin_size_bits)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        return -1;
    }
    if (data->arch_data) {
        ZF_LOGE("Double-initialized! arch_data is not NULL");
        return -1;
    }

    data->base_physical_address = paddr;
    data->frame_sequence = fcs;
    data->largest_avail_frame_number_bits = origin_size_bits;

#if CONFIG_WORD_SIZE == 32
    ;
#else
    data->arch_data = (arch64_two_level_bitmap_t *)malloc(sizeof(arch64_two_level_bitmap_t));
    if (!data->arch_data) {
        ZF_LOGE("Failed to allocate memory for arch_data in vbt_t");
        return -1;
    }
    data->arch_data = (arch64_two_level_bitmap_t *)memset(data->arch_data, 0, sizeof(arch64_two_level_bitmap_t));

    arch64_vbt_make_interface(data->arch_data);

    data->arch_data->arch_init(data->arch_data->data);
#endif
    return seL4_NoError;
}

/***
 * Query a virtual-bitmap-tree and try to find an available memory region that can
 * serve the memory request, return 'cookie', architecture independent function
 * 
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param real_size : size (number of frames + frame_size in bits) of the requested memory region
 * @param paddr : (deprecated?) physical address of the requested memory region
 * 
 * @return cookie : result, architecture dependent, passed to 'Arch_vbt_' interfaces
 */
void *vbt_query_avail_memory_region(vbt_t *data, size_t real_size, uintptr_t paddr)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        return NULL;
    }
    if (!data->arch_data) {
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        return NULL;
    }
    
    size_t fn = real_size - seL4_PageBits;

#if CONFIG_WORD_SIZE == 32
    return NULL;
#else
    void *cell = malloc(sizeof(address_cell_t));
    if (!cell) {
        ZF_LOGE("Failed to allocate space for vbt query cookie");
        return NULL;
    }
    cell = memset(cell, 0, sizeof(address_cell_t));

    data->arch_data->arch_query_avail_mr(data->arch_data->data, fn, cell);
/* FIXME */
    return cell;
#endif
}

/* Debug function ? */
void vbt_query_try_cookie_release(void *cookie)
{
#if CONFIG_WORD_SIZE == 32
    free(cookie);   /* deprecated now */
#else
    cookie = (address_cell_t *)cookie;
    free(cookie); /* Maybe we can do it anywhere? */
#endif
}

/***
 * Acquire an memory region (as requested) from a virtual-bitmap-tree and try
 * updating the status of the tree.
 * 
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param cookie : result, architecture dependent, passed to 'Arch_vbt_' interfaces
 */
void vbt_update_memory_region_acquired(vbt_t *data, void *cookie)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        return;
    }
    if (!data->arch_data) {
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        return;
    }
#if CONFIG_WORD_SIZE == 32
    ;
#else
    data->arch_data->arch_acquire_mr(data->arch_data->data, cookie);
    data->largest_avail_frame_number_bits = data->arch_data->arch_update_largest(data->arch_data->data);
#endif
}

/***
 * Release an allocated memory region to its original virtual-bitmap-tree and try
 * updating the status of the tree.
 * 
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param cptr : <TODO>
 */
void vbt_update_memory_region_released(vbt_t *data, seL4_CPtr cptr)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        return;
    }
    if (!data->arch_data) {
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        return;
    }
#if CONFIG_WORD_SIZE == 32
    ;
#else
    address_cell_t cell;

    cell.i1 = 32 + (cptr - data->frame_sequence.capPtr) / 32;
    cell.i2 = 32 + (cptr - data->frame_sequence.capPtr) % 32;

    data->arch_data->arch_release_mr(data->arch_data->data, &cell);
    data->largest_avail_frame_number_bits = data->arch_data->arch_update_largest(data->arch_data->data);
#endif
}

seL4_CPtr vbt_calculate_target_frame_cptr_offset(vbt_t *data, const void *cookie)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        assert(0);
    }
    if (!data->arch_data) {
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        assert(0);
    }
    if (!cookie) {
        ZF_LOGE("Failed to calculate frame offset based on empty cookie");
        assert(0);
    }
#if CONFIG_WORD_SIZE == 32
    return NULL;
#else
    return data->arch_data->arch_frame_offset(cookie);
#endif
}
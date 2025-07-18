
#include <allocman/allocman.h>
#include <allocman/vbt.h>
#include <assert.h>
#include <string.h>
#include <utils/util.h>

#if CONFIG_WORD_SIZE == 32
    #define ARCH_INSTANCE(x) arch32_##x
#elif CONFIG_WORD_SIZE == 64
    #define ARCH_INSTANCE(x) arch64_##x
#else
    #error "Unsupported WORD_SIZE value"
#endif

/***
 * Initialize a virtual-bitmap-tree.
 * 
 * @param alloc : allocator for bootstrapping
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param paddr : physical address of the requested memory region
 * @param fcs : frames cptr sequence (compressed in one 'cspacepath_t' variable)
 * @param origin_size_bits : default available memory region size of the tree, (should be 10+12)
 */
int vbt_instance_init(void *alloc, vbt_t *data, uintptr_t paddr, cspacepath_t fcs, size_t origin_size_bits)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        return -1;
    }
    if (data->arch_data) {
        ZF_LOGE("Double-initialized! arch_data is not NULL");
        return -1;
    }
    if (!alloc) {
        ZF_LOGE("no allocator is given for bootstrapping");
        return -1;
    }
    allocman_t *a = (allocman_t *)alloc;

    data->base_physical_address = paddr;
    data->frame_sequence = fcs;
    data->largest_avail = origin_size_bits;

    int err;
#if CONFIG_WORD_SIZE == 32
    data->arch_data = (arch32_single_level_bitmap_t *)allocman_mspace_alloc(a, sizeof(arch32_single_level_bitmap_t), &err);
    if (!data->arch_data || err) {
        ZF_LOGE("Failed to allocate memory for arch_data in vbt_t");
        return -1;
    }
    data->arch_data = (arch32_single_level_bitmap_t *)memset(data->arch_data, 0, sizeof(arch32_single_level_bitmap_t));
#else
    data->arch_data = (arch64_two_level_bitmap_t *)allocman_mspace_alloc(a, sizeof(arch64_two_level_bitmap_t), &err);
    if (!data->arch_data || err) {
        ZF_LOGE("Failed to allocate memory for arch_data in vbt_t");
        return -1;
    }
    data->arch_data = (arch64_two_level_bitmap_t *)memset(data->arch_data, 0, sizeof(arch64_two_level_bitmap_t));
#endif
    ARCH_INSTANCE(vbt_make_interface)(data);
    /* arch32/64_vbt_make_interface(data); */
    data->arch_data->arch_init(data->arch_data);

    return seL4_NoError;
}

/***
 * Query a virtual-bitmap-tree and try to find an available memory region that can
 * serve the memory request, return 'cookie', architecture independent function
 * 
 * @param alloc : allocator for bootstrapping
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param real_size : size (number of frames + frame_size in bits) of the requested memory region
 * @param err : query result validity
 * 
 * @return cookie : result, architecture dependent, passed to 'Arch_vbt_' interfaces
 */
void *vbt_query_avail_memory_region(void *alloc, vbt_t *data, size_t real_size, int *err)
{
    if (!data) {
        *err = -1;
        ZF_LOGE("vbt_data is NULL");
        return NULL;
    }
    if (!data->arch_data) {
        *err = -1;
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        return NULL;
    }
    if (!alloc) {
        *err = -1;
        ZF_LOGE("no allocator is given for bootstrapping");
        return NULL;
    }
    allocman_t *a = (allocman_t *)alloc;
    
    size_t fn = real_size - seL4_PageBits;
    /***
     * FIXME:
     * We don't know the cookie type when we are invoking CapBuddy interfaces
     * to query & acquire memory regions, so it's something we can't avoid to
     * know cookie type in here.
     */
    void *cell;

#if CONFIG_WORD_SIZE == 32
    /***
     * It turns out that we can use frame offset in array as reference cookie
     * in single-level virtual-bitmap-tree structure. (it will be no more
     * than 2048 and larger than 0, 1->4M, 2~3->2M, 4~7->1M, 8~15->512k ...)
     */
    cell = allocman_mspace_alloc(a, sizeof(address_index_t), err);
    if (!cell || *err) {
        *err = -1;
        ZF_LOGE("Failed to allocate space for vbt query cookie");
        return NULL;
    }
    cell = memset(cell, 0, sizeof(address_index_t));
#else
    cell = allocman_mspace_alloc(a, sizeof(address_cell_t), err);
    if (!cell || *err) {
        *err = -1;
        ZF_LOGE("Failed to allocate space for vbt query cookie");
        return NULL;
    }
    cell = memset(cell, 0, sizeof(address_cell_t));
#endif
    /* Real work */
    data->arch_query_avail_mr(data->arch_data, fn, cell, err);
    if (*err != seL4_NoError) {
        /* No available memory region for the request */
        vbt_query_try_cookie_release(alloc, cell);
        return NULL;
    }
    /* We are doing fine in here. */
    return cell;
}

/***
 * Query a virtual-bitmap-tree and try to find an available memory region at specific
 * physical address that can serve the memory request, return 'cookie', architecture
 * independent function
 * 
 * @param alloc : allocator for bootstrapping
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param real_size : size (number of frames + frame_size in bits) of the requested memory region
 * @param paddr : physical address of the requested memory region
 * @param err : query result validity
 * 
 * @return cookie : result, architecture dependent, passed to 'Arch_vbt_' interfaces
 */
void *vbt_query_avail_memory_region_at(void *alloc, vbt_t *data, size_t real_size, uintptr_t paddr, int *err)
{
    if (!data) {
        *err = -1;
        ZF_LOGE("vbt_data is NULL");
        return NULL;
    }
    if (!data->arch_data) {
        *err = -1;
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        return NULL;
    }
    if (!alloc) {
        *err = -1;
        ZF_LOGE("no allocator is given for bootstrapping");
        return NULL;
    }
    allocman_t *a = (allocman_t *)alloc;
    
    size_t fn = real_size - seL4_PageBits;
    /***
     * FIXME:
     * We don't know the cookie type when we are invoking CapBuddy interfaces
     * to query & acquire memory regions, so it's something we can't avoid to
     * know cookie type in here.
     */
    void *cell;

#if CONFIG_WORD_SIZE == 32
    /***
     * It turns out that we can use frame offset in array as reference cookie
     * in single-level virtual-bitmap-tree structure. (it will be no more
     * than 2048 and larger than 0, 1->4M, 2~3->2M, 4~7->1M, 8~15->512k ...)
     */
    cell = allocman_mspace_alloc(a, sizeof(address_index_t), err);
    if (!cell || *err) {
        *err = -1;
        ZF_LOGE("Failed to allocate space for vbt query cookie");
        return NULL;
    }
    cell = memset(cell, 0, sizeof(address_index_t));
#else
    cell = allocman_mspace_alloc(a, sizeof(address_cell_t), err);
    if (!cell || *err) {
        *err = -1;
        ZF_LOGE("Failed to allocate space for vbt query cookie");
        return NULL;
    }
    cell = memset(cell, 0, sizeof(address_cell_t));
#endif
    /***
     * Architectual virtual-bitmap-tree metadata does not contain physical
     * memory address of the original untyped object, so it's not feasible
     * to utilize paddr directly.
     */
    uintptr_t untyped_paddr = data->base_physical_address;
    size_t idx = (paddr - untyped_paddr) / (1U << seL4_PageBits);

    /* invoke by using index of frame instead */
    data->arch_query_avail_mr_at(data->arch_data, idx, fn, cell, err);
    if (*err != seL4_NoError) {
        /* No available memory region for the request */
        vbt_query_try_cookie_release(alloc, cell);
        return NULL;
    }
    return cell;
}

/* Debug function ? */
void vbt_query_try_cookie_release(void *alloc, void *cookie)
{
    if (!alloc) {
        ZF_LOGE("no allocator is given for bootstrapping");
        /* internal allocator error */
        assert(alloc);
    }
    allocman_t *a = (allocman_t *)alloc;

#if CONFIG_WORD_SIZE == 32
    cookie = (address_index_t *)cookie;
    allocman_mspace_free(a, cookie, sizeof(address_index_t));
#else
    cookie = (address_cell_t *)cookie;
    allocman_mspace_free(a, cookie, sizeof(address_cell_t));
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
    data->arch_acquire_mr(data->arch_data, cookie);
    data->largest_avail = data->arch_update_largest(data->arch_data);
}

/***
 * Release an allocated memory region to its original virtual-bitmap-tree and try
 * updating the status of the tree.
 * 
 * @param data : target virtual-bitmap-tree with architectural supports
 * @param cptr : <TODO>
 */
void vbt_update_memory_region_released(vbt_t *data, seL4_CPtr cptr, size_t num_bits)
{
    if (!data) {
        ZF_LOGE("vbt_data is NULL");
        return;
    }
    if (!data->arch_data) {
        ZF_LOGE("vbt arch_data is NULL, initialize it first");
        return;
    }
    /***
     * num_bits:
     *  -> number of frames in the block to release.
     *  -> 0 means BIT(0)=1, only 1 frame to free
     *  -> 1 for 2, 2 for 4, ...
     *      -> maximum = 10? -> 1024
     */
    if (num_bits > 10) {
        ZF_LOGE("allocman: super large block free batching unimplemented yet");
        return;
    }
    //
    // TODO:
    //      currently no batching for 32 bit!
    //
#if CONFIG_WORD_SIZE == 32

    address_index_t cell;
    cell.idx = cptr - data->frame_sequence.capPtr + 1024;

#else /* 64 bit machine word */

    /* address of the memory block to release */
    address_cell_t cell;

    if (num_bits > BITMAP_LEVEL) {
        /* l1 bitmap */
        cell.i1 = L1IDX(num_bits) + (cptr - data->frame_sequence.capPtr) / (1ULL << num_bits);
        cell.i2 = 0;
    } else {
        /* offset within the level 2 bitmap */
        size_t offset_l2;
        /* from within l2, the calculation is the same to l1 */
        offset_l2 = (cptr - data->frame_sequence.capPtr) % 32;
        /* base: 32, because all l2 bitmap bits are between 32 and 63 */
        cell.i1 = 32 + (cptr - data->frame_sequence.capPtr) / 32;
        /* base: depends on the block size */
        cell.i2 = L2IDX(num_bits) + offset_l2 / (1ULL << num_bits);
    }

#endif

    data->arch_release_mr(data->arch_data, &cell);
    data->largest_avail = data->arch_update_largest(data->arch_data);
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
    return data->arch_frame_offset(cookie);
}
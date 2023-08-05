
#pragma once

#include <autoconf.h>
#include <sel4/types.h>
#include <allocman/cspace/cspace.h>

#if CONFIG_WORD_SIZE == 32
    #include <allocman/vbt/arch32.h>
#elif CONFIG_WORD_SIZE == 64
    #include <allocman/vbt/arch64.h>
#else
    #error "Unsupported WORD_SIZE value"
#endif

typedef struct virtual_bitmap_tree {
    /***
     * @param: arch_data: architecture dependent virtual-bitmap-tree data
     *         pointer. It contains architectural information and methods
     *         that support implementing virtual-bitmap-tree in different
     *         machine-wordsize working environment.
     */
#if CONFIG_WORD_SIZE == 32
    arch32_single_level_bitmap_t *arch_data;
#else /* 64 arch */
    arch64_two_level_bitmap_t *arch_data;
#endif
    /* base address of the original untyped object & frame_sequence */
    uintptr_t base_physical_address;
    /* compressed metadata for frames retyped from the original untyped */
    cspacepath_t frame_sequence;
    /* current largest available memory region size in bits of frame number */
    size_t largest_avail_frame_number_bits;
    
    arch_vbt_update_largest_fn arch_update_largest;
    arch_vbt_query_avail_mr_fn arch_query_avail_mr;
    arch_vbt_acquire_mr_fn arch_acquire_mr;
    arch_vbt_release_mr_fn arch_release_mr;
    arch_vbt_retrieve_page_id_fn arch_frame_offset;

    struct virtual_bitmap_tree *next;
    struct virtual_bitmap_tree *prev;

} vbt_t;

int vbt_instance_init(vbt_t *data, uintptr_t paddr, cspacepath_t fcs, size_t origin_size_bits);

void *vbt_query_avail_memory_region(vbt_t *data, size_t real_size, int *err);

void *vbt_query_avail_memory_region_at(vbt_t *data, size_t real_size, uintptr_t paddr, int *err);

void vbt_query_try_cookie_release(void *cookie);

void vbt_update_memory_region_acquired(vbt_t *data, void *cookie);

void vbt_update_memory_region_released(vbt_t *data, seL4_CPtr cptr);

seL4_CPtr vbt_calculate_target_frame_cptr_offset(vbt_t *data, const void *cookie);

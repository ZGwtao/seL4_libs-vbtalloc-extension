/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <allocman/cspace/single_level.h>
#include <allocman/util.h>
#include <allocman/allocman.h>
#include <sel4/sel4.h>
#include <string.h>

#define BITS_PER_WORD (sizeof(size_t) * 8)

int cspace_single_level_create(struct allocman *alloc, cspace_single_level_t *cspace, struct cspace_single_level_config config)
{
    size_t num_slots;
    size_t num_entries;
    int error;
    cspace->config = config;
    /* Allocate bitmap */
    num_slots = cspace->config.end_slot - cspace->config.first_slot;
    num_entries = num_slots / BITS_PER_WORD;
    cspace->bitmap_length = num_entries;
    if (num_slots % BITS_PER_WORD != 0) {
        num_entries++;
    }
    cspace->bitmap = (size_t*)allocman_mspace_alloc(alloc, num_entries * sizeof(size_t), &error);
    if (error) {
        return error;
    }
    /* Make everything 1's */
    memset(cspace->bitmap, -1, num_entries * sizeof(size_t));
    if (num_slots % BITS_PER_WORD != 0) {
        /* Mark the padding slots as allocated */
        size_t excess = num_slots % BITS_PER_WORD;
        size_t i;
        for (i = excess; i < BITS_PER_WORD; i++) {
            cspace->bitmap[num_entries - 1] ^= BIT(i);
        }
    }
#ifdef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS
    cspace->last_entry = num_entries / 2;
    cspace->contiguous_limit = num_entries / 2;
    cspace->contiguous_watermark = 0;
#else
    cspace->last_entry = 0;
#endif
    return 0;
}

void cspace_single_level_destroy(struct allocman *alloc, cspace_single_level_t *cspace)
{
    allocman_mspace_free(alloc, cspace->bitmap, cspace->bitmap_length * sizeof(size_t));
}

int _cspace_single_level_alloc_at(allocman_t *alloc, void *_cspace, seL4_CPtr slot) {
    cspace_single_level_t *cspace = (cspace_single_level_t*)_cspace;
    size_t index = slot - cspace->config.first_slot;
    /* make sure index is in range */
    if (index / BITS_PER_WORD >= cspace->bitmap_length) {
        return 1;
    }
    /* make sure not already allocated */
    if ( (cspace->bitmap[index / BITS_PER_WORD] & BIT(index % BITS_PER_WORD)) == 0) {
        return 1;
    }
    /* mark it as allocated */
    cspace->bitmap[index / BITS_PER_WORD] &= ~BIT(index % BITS_PER_WORD);
    return 0;
}

#ifndef CONFIG_LIB_ALLOCMAN_ALLOW_POOL_OPERATIONS

int _cspace_single_level_alloc(allocman_t *alloc, void *_cspace, cspacepath_t *slot)
{
    size_t i;
    size_t index;
    cspace_single_level_t *cspace = (cspace_single_level_t*)_cspace;
    i = cspace->last_entry;
    if (cspace->bitmap[i] == 0) {
        assert(cspace->bitmap_length != 0);
        assert(cspace->last_entry < cspace->bitmap_length);
        do {
            i = (i + 1) % cspace->bitmap_length;
        } while (cspace->bitmap[i] == 0 && i != cspace->last_entry);
        if (i == cspace->last_entry) {
            return 1;
        }
        cspace->last_entry = i;
    }
    index = BITS_PER_WORD - 1 - CLZL(cspace->bitmap[i]);
    cspace->bitmap[i] &= ~BIT(index);
    *slot = _cspace_single_level_make_path(cspace, cspace->config.first_slot + (i * BITS_PER_WORD + index));
    return 0;
}

void _cspace_single_level_free(allocman_t *alloc, void *_cspace, const cspacepath_t *slot)
{
    cspace_single_level_t *cspace = (cspace_single_level_t*)_cspace;
    size_t index = slot->capPtr - cspace->config.first_slot;
    assert((cspace->bitmap[index / BITS_PER_WORD] & BIT(index % BITS_PER_WORD)) == 0);
    cspace->bitmap[index / BITS_PER_WORD] |= BIT(index % BITS_PER_WORD);
}

#else

static size_t cspace_find_avail_bitmap(cspace_single_level_t *cspace)
{
    size_t i = cspace->last_entry;
    if (cspace->bitmap[i] == 0) {
        assert(cspace->bitmap_length != 0);
        assert(cspace->last_entry < cspace->bitmap_length);
        do {
            i = (i + 1) % cspace->bitmap_length;
            if (i == 0) {
                i = cspace->contiguous_limit;
            }
        } while (cspace->bitmap[i] == 0 && i != cspace->last_entry);
        if (i == cspace->last_entry) {
            return (size_t)-1;
        }
        cspace->last_entry = i;
    }
    return i;
}

int _cspace_single_level_alloc(allocman_t *alloc, void *_cspace, cspacepath_t *slot)
{
    cspace_single_level_t *cspace = (cspace_single_level_t*)_cspace;
    size_t i = cspace_find_avail_bitmap(cspace);
    if (i == (size_t)-1) {
        return 1;
    }
    size_t offset = CLZL(cspace->bitmap[i]);
    cspace->bitmap[i] &= ~BIT((BITS_PER_WORD) - offset - 1);
    *slot = _cspace_single_level_make_path(cspace, cspace->config.first_slot + (i * BITS_PER_WORD + offset));
    return 0;
}

void _cspace_single_level_free(allocman_t *alloc, void *_cspace, const cspacepath_t *slot)
{
    cspace_single_level_t *cspace = (cspace_single_level_t*)_cspace;
    size_t index = slot->capPtr - cspace->config.first_slot;
    size_t offset = index % BITS_PER_WORD;
    size_t base = index / BITS_PER_WORD;
    assert(!(cspace->bitmap[base] & BIT((BITS_PER_WORD) - offset - 1)));
    cspace->bitmap[base] |= BIT((BITS_PER_WORD) - offset - 1);
}

int _cspace_single_level_csa(struct allocman *alloc, void *_cspace, cspacepath_t *slots, size_t num_bits)
{
    cspace_single_level_t *cspace = (cspace_single_level_t *)_cspace;
#define _MASK_FOR_HEAD_(X) ((BIT(BITS_PER_WORD - (X)) - 1ul))
    size_t num = BIT(num_bits);
    size_t watermark = cspace->contiguous_watermark;
    size_t remains = cspace->contiguous_limit * BITS_PER_WORD - watermark;
    size_t offset = cspace->contiguous_watermark % BITS_PER_WORD;
    size_t base = cspace->contiguous_watermark / BITS_PER_WORD;

    if (num > remains) {
        return 1;
    }

    cspace->contiguous_watermark += num;

    if (num <= BITS_PER_WORD - offset) {
        cspace->bitmap[base] &= _MASK_FOR_HEAD_(offset + num);
    } else {
        size_t new_offset = cspace->contiguous_watermark % BITS_PER_WORD;
        size_t new_base = cspace->contiguous_watermark / BITS_PER_WORD;
        for (size_t i = base; i < new_base; ++i) {
            cspace->bitmap[i] &= 0ul;
        }
        cspace->bitmap[new_base] &= _MASK_FOR_HEAD_(new_offset);
    }
#undef _MASK_FOR_HEAD_
    slots->root = cspace->config.cnode;
    slots->capPtr = cspace->config.first_slot + watermark;
    slots->capDepth = cspace->config.cnode_size_bits + cspace->config.cnode_guard_bits;
    slots->dest = 0;
    slots->destDepth = 0;
    slots->offset = cspace->config.first_slot + watermark;
    slots->window = num;
    return 0;
}

int _cspace_single_level_pool(struct allocman *alloc, void *_cspace, seL4_CPtr slot, size_t num_bits)
{
    size_t bound;
    size_t num_slots;
    cspace_single_level_t *cspace;    
    cspace = (cspace_single_level_t *)_cspace;
    /* csa upper boundary */
    bound = cspace->contiguous_limit * BITS_PER_WORD;
    /* number of slots starting at var:slot */
    num_slots = (1UL << num_bits) - 1;

    /* determine if this region is within the csa area */
    if ((slot - cspace->config.first_slot) < bound) {
        if ((slot + num_slots - cspace->config.first_slot) < bound) {
            return 1;
        }
    }
    return 0;
}

#endif
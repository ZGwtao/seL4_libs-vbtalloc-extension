
#include <allocman/vbt/interface.h>

#define BITMAP_DEPTH            6
#define BITMAP_SIZE             64
#define BITMAP_SUB_OFFSET(X)    ((X) - 32)
#define BITMAP_LEVEL            ((BITMAP_DEPTH) - 1)
#define VBT_PAGE_GRAIN          seL4_PageBits
#define VBT_INDEX_BIT(X)        BIT(((BITMAP_SIZE) - 1) - (X))
#define BITMAP_GET_LEVEL(X)     ((BITMAP_SIZE) - CLZL(X))
#define BITMAP_INDEX(SZ)        (1 << ((BITMAP_LEVEL) - (SZ)))
#define L1IDX(SZ)  BITMAP_INDEX((SZ) - (BITMAP_LEVEL))
#define L2IDX(SZ)  BITMAP_INDEX(SZ)
#define VBT_AND(WORDA,WORDB)    ((WORDA) & (WORDB))
#define VBT_ORR(WORDA,WORDB)    ((WORDA) | (WORDB))

typedef struct address_cell {
    /***
     * 1. index of level_1 bitmap of the target memory region
     * 2. index of level_2 bitmap of the target memory region
     * 
     * NOTICE:
     *  level_2 > 0 only when target memory region size is
     *  smaller than 256k (i.e., 128k ~ 4k)
     */
    int i1, i2;

} address_cell_t; 

typedef struct _bitmap_64_ {
    /***
     * [true] denotes the virtual memory region is available;
     * [false] denotes the region is unavailable or reserved;
     */
    size_t map;

} arch64_bitmap_t;

typedef struct two_level_bitmap {
/***
 *  largest_cell -> architecture dependent, we need
 *     to split it from the data structure to write
 *     architecture independent codes.
 */
    address_cell_t largest_cell;
/***
 *  bitmap information is also architecture dependent,
 *  like @param 'largest_cell'
 */    
    arch64_bitmap_t l1;
    arch64_bitmap_t l2[32];
/* architectural initializing interface */
    arch_vbt_init_fn arch_init;

} arch64_two_level_bitmap_t;

void arch64_vbt_make_interface(void *data);

#include <allocman/vbt/interface.h>

typedef struct _bitmap_32_ {

    size_t map;

} arch32_bitmap_t;

typedef struct single_level_bitmap {
    /***
     * bitmap array line-up:
     * ----------------------------------------------------
     * [ 0 ][0~31] : [0]->reserved bit, [1]->4M, [2~3]->2M
     *               [4~7]->1M, [8~15]->512k, [16~31]->256k
     * ----------------------------------------------------
     * [ 1 ][0~31] : [0~31]->128k
     * ----------------------------------------------------
     * [2~3][0~31] : [0~31]->64k
     * ----------------------------------------------------
     * [4~7][0~31] : [0~31]->32k
     * ----------------------------------------------------
     * [8~15][~31] : [0~31]->16k
     * ----------------------------------------------------
     * [16~31][~] : -> 8k
     * ----------------------------------------------------
     * [32~63][~] : -> 4k => 32 * 32 = 1024 pages
     * ----------------------------------------------------
     */
    arch32_bitmap_t bma[64];

    void *data;

} arch32_single_level_bitmap_t;

void arch32_vbt_make_interface(void *data);

libsel4vka-vbtalloc-extension
==================================
Original implementation see: [libsel4vka](https://github.com/seL4/seL4_libs/tree/master/libsel4vka). This is the implementation of vka interafces that CapBuddy memory management support for seL4 LibOS may need based on libsel4vka.

New features
------------
* vka_utspace_try_alloc_from_pool => Allocate frame object from the CapBuddy memory pool
* vka_utspace_try_free_from_pool => Release frame object from the memory pool back to CapBuddy
* vka_cspace_is_from_pool => Query the capability index of a given object to determine if it is a frame object from the memory pool

libsel4allocman-vbtalloc-extension
==================================
Original implementation see: [libsel4allocman](https://github.com/seL4/seL4_libs/tree/master/libsel4allocman), this is the implementation of CapBuddy memory management support for seL4 LibOS based on libsel4allocman kernel object allocator.

New features
------------
* Bitmap Buddy System support for CapBuddy => vbt-related functions implemented in [here](https://github.com/ZGwtao/seL4_libs-vbtalloc-extension/blob/master/libsel4allocman/src/allocman.c)
* Implementation of new libsel4vka (check [README](https://github.com/ZGwtao/seL4_libs-vbtalloc-extension)) interfaces => 
     *1. am_vka_utspace_try_alloc_from_pool*
     *2. am_vka_utspace_try_free_from_pool*
     *3. am_vka_cspace_is_from_pool*
* Multiple capabilities allocation from single level cspace => contiguous capabilities at CNode (which means their capability slots are adjacent in capTable)

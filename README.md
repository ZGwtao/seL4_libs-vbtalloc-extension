
# CapBuddy MM support based on seL4 LibOS utils
This project aims to provide an example implementation of the ```CapBuddy``` memory management support based on seL4 LibOS utilities. CapBuddy MM support is now implemented as a buffer utility besides real untyped allocator (i.e. *allocman*). When receiving *alloc* demands, it will at first hand check if the memory pools are empty or not. If so, it returns a metadata describing an available memory region (i.e. capability pointers of contiguous frames), otherwise, by retyping and slicing an untyped object (size: 4M) into a batch of frame objects (size: 4K), one new memory pool will be created.

## Overview
*Major modifications in seL4_Libs project:*
* libsel4allocman-vbt-extension => CapBuddy implementation
* libsel4vka-vbt-extension => New interfaces design for CapBuddy

*New Interfaces:*
1. (vka) utspace_try_alloc_from_pool => Frame allocation (multiple allocation included)
2. (vka) utspace_try_free_from_pool => Frame deallocation (from pool), user need to ensure the metadata belongs to a frame from pool
3. (vka) cspace_is_from_pool => To distinguish if the frame is from pool or real untyped object allocator

*System requirements:*
When building a project with the support of CapBuddy in libsel4allocman and libsel4vka, one can use the building method provided by [sel4test](https://github.com/seL4/sel4test-manifest.git) and [seL4 Buildsystem](https://docs.sel4.systems/projects/buildsystem/using.html). Some CMake options should also be added:

* -DLibVKAAllowPoolOperations=ON (CapBuddy support)
* -DLibAllocmanAllowPoolOperations=ON (CapBuddy support)
* -DKernelRetypeFanOutLimit=1024 (4M -> pre-allocation 1024 4K)
* -DKernelRootCNodeSizeBits=18 (or larger, just for recommendation)
* -DLibSel4MuslcSysMorecoreBytes=0 (for libsel4muslcsys, when pager is missing, and we still want a dynamic heap)
* -DKernelBenchmarks=track_utilisation (for benchmarking purpose)
         
## Others
*Future work:*
* (TODO) Instead of modifying libsel4allocman, providing a new seL4 kernel objects allocator on top of libsel4vka interface is considered. 
* (TODO) Device releated untyped objects management in CapBuddy.


#pragma once

#include <autoconf.h>
#include <sel4/types.h>
#include <utils/util.h>

typedef void (*arch_vbt_init_fn)(void *data);

typedef size_t (*arch_vbt_update_largest_fn)(void *data);

typedef void (*arch_vbt_query_avail_mr_fn)(void *data, size_t fn, void *res);

typedef void (*arch_vbt_acquire_mr_fn)(void *data, const void *cookie);

typedef void (*arch_vbt_release_mr_fn)(void *data, const void *cookie);

typedef seL4_CPtr (*arch_vbt_retrieve_page_id_fn)(const void *cookie);

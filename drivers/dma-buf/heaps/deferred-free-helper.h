/* SPDX-License-Identifier: GPL-2.0 */

#ifndef DEFERRED_FREE_HELPER_H
#define DEFERRED_FREE_HELPER_H

struct deferred_freelist_item {
	size_t size;
	void (*free)(struct deferred_freelist_item *i, bool no_pool);
	struct list_head list;
};

void deferred_free(struct deferred_freelist_item *item,
		   void (*free)(struct deferred_freelist_item *i, bool no_pool),
		   size_t size);
#endif

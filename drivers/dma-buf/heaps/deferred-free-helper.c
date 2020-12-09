// SPDX-License-Identifier: GPL-2.0
/*
 * Deferred dmabuf freeing helper
 *
 * Copyright (C) 2020 Linaro, Ltd.
 *
 * Based on the ION page pool code
 * Copyright (C) 2011 Google, Inc.
 */

#include <linux/freezer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/sched/signal.h>

#include "deferred-free-helper.h"

static LIST_HEAD(free_list);
static size_t list_size;
wait_queue_head_t freelist_waitqueue;
struct task_struct *freelist_task;
static DEFINE_MUTEX(free_list_lock);

enum {
	USE_POOL = 0,
	SKIP_POOL = 1,
};

void deferred_free(struct deferred_freelist_item *item,
		   void (*free)(struct deferred_freelist_item*, bool),
		   size_t size)
{
	INIT_LIST_HEAD(&item->list);
	item->size = size;
	item->free = free;

	mutex_lock(&free_list_lock);
	list_add(&item->list, &free_list);
	list_size += size;
	mutex_unlock(&free_list_lock);
	wake_up(&freelist_waitqueue);
}

static size_t free_one_item(bool nopool)
{
	size_t size = 0;
	struct deferred_freelist_item *item;

	mutex_lock(&free_list_lock);
	if (list_empty(&free_list)) {
		mutex_unlock(&free_list_lock);
		return 0;
	}
	item = list_first_entry(&free_list, struct deferred_freelist_item, list);
	list_del(&item->list);
	size = item->size;
	list_size -= size;
	mutex_unlock(&free_list_lock);

	item->free(item, nopool);
	return size;
}

static unsigned long get_freelist_size(void)
{
	unsigned long size;

	mutex_lock(&free_list_lock);
	size = list_size;
	mutex_unlock(&free_list_lock);
	return size;
}

static unsigned long freelist_shrink_count(struct shrinker *shrinker,
					   struct shrink_control *sc)
{
	return get_freelist_size();
}

static unsigned long freelist_shrink_scan(struct shrinker *shrinker,
					  struct shrink_control *sc)
{
	int total_freed = 0;

	if (sc->nr_to_scan == 0)
		return 0;

	while (total_freed < sc->nr_to_scan) {
		int freed = free_one_item(SKIP_POOL);

		if (!freed)
			break;

		total_freed += freed;
	}

	return total_freed;
}

static struct shrinker freelist_shrinker = {
	.count_objects = freelist_shrink_count,
	.scan_objects = freelist_shrink_scan,
	.seeks = DEFAULT_SEEKS,
	.batch = 0,
};

static int deferred_free_thread(void *data)
{
	while (true) {
		wait_event_freezable(freelist_waitqueue,
				     get_freelist_size() > 0);

		free_one_item(USE_POOL);
	}

	return 0;
}

static int deferred_freelist_init(void)
{
	list_size = 0;

	init_waitqueue_head(&freelist_waitqueue);
	freelist_task = kthread_run(deferred_free_thread, NULL,
				    "%s", "dmabuf-deferred-free-worker");
	if (IS_ERR(freelist_task)) {
		pr_err("%s: creating thread for deferred free failed\n",
		       __func__);
		return -1;
	}
	sched_set_normal(freelist_task, 19);

	return register_shrinker(&freelist_shrinker);
}
device_initcall(deferred_freelist_init);

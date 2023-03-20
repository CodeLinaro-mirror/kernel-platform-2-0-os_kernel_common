// SPDX-License-Identifier: GPL-2.0-only

#include <linux/pagemap.h>
#include <linux/xarray.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <asm/mte.h>

static DEFINE_XARRAY(tags_by_swp_entry);

void *mte_allocate_tags_mem(void)
{
	/* tags granule is 16 bytes, 2 tags stored per byte */
	return kmalloc(MTE_PAGE_TAG_STORAGE_SIZE, GFP_KERNEL);
}

void mte_free_tags_mem(void *tags)
{
	kfree(tags);
}

int mte_save_page_tags_by_swp_entry(struct page *page)
{
	void *tags, *ret;

	if (!page_mte_tagged(page))
		return 0;

	tags = mte_allocate_tags_mem();
	if (!tags)
		return -ENOMEM;

	mte_save_page_tags_to_mem(page_address(page), tags);

	/* page_private contains the swap entry.val set in do_swap_page */
	ret = xa_store(&tags_by_swp_entry, page_private(page), tags, GFP_KERNEL);
	if (WARN(xa_is_err(ret), "Failed to store MTE tags")) {
		mte_free_tags_mem(tags);
		return xa_err(ret);
	} else if (ret) {
		/* Entry is being replaced, free the old entry */
		mte_free_tags_mem(ret);
	}

	return 0;
}

void mte_restore_page_tags_by_swp_entry(swp_entry_t entry, struct page *page)
{
	void *tags = xa_load(&tags_by_swp_entry, entry.val);

	if (!tags)
		return;

	/*
	 * Test PG_mte_tagged in case the tags were restored before
	 * (e.g. CoW pages).
	 */
	if (!test_and_set_bit(PG_mte_tagged, &page->flags))
		mte_restore_page_tags_from_mem(page_address(page), tags);
}

void mte_invalidate_tags_by_swp_entry(int type, pgoff_t offset)
{
	swp_entry_t entry = swp_entry(type, offset);
	void *tags = xa_erase(&tags_by_swp_entry, entry.val);

	mte_free_tags_mem(tags);
}

void mte_invalidate_tags_area_by_swp_entry(int type)
{
	swp_entry_t entry = swp_entry(type, 0);
	swp_entry_t last_entry = swp_entry(type + 1, 0);
	void *tags;

	XA_STATE(xa_state, &tags_by_swp_entry, entry.val);

	xa_lock(&tags_by_swp_entry);
	xas_for_each(&xa_state, tags, last_entry.val - 1) {
		__xa_erase(&tags_by_swp_entry, xa_state.xa_index);
		mte_free_tags_mem(tags);
	}
	xa_unlock(&tags_by_swp_entry);
}

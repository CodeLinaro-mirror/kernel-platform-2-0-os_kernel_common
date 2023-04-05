/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_MEMORY_METADATA_H
#define __ASM_GENERIC_MEMORY_METADATA_H

#include <linux/gfp.h>
#include <linux/mm_types.h>

extern unsigned long totalmetadata_pages;

#ifndef CONFIG_MEMORY_METADATA
static inline bool metadata_storage_enabled(void)
{
	return false;
}
static inline bool alloc_can_use_metadata_pages(gfp_t gfp_mask)
{
	return false;
}
static inline bool page_has_metadata(struct page *page)
{
	return false;
}
#endif /* !CONFIG_MEMORY_METADATA */

#endif /* __ASM_GENERIC_MEMORY_METADATA_H */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 ARM Ltd.
 */
#ifndef __ASM_MEMORY_METADATA_H
#define __ASM_MEMORY_METADATA_H

#include <asm-generic/memory_metadata.h>

#include <asm/mte.h>

#ifdef CONFIG_MEMORY_METADATA
static inline bool metadata_storage_enabled(void)
{
	return false;
}
static inline bool alloc_can_use_metadata_pages(gfp_t gfp_mask)
{
	return false;
}

#define page_has_metadata(page)			page_mte_tagged(page)

#endif /* CONFIG_MEMORY_METADATA */

#endif /* __ASM_MEMORY_METADATA_H  */

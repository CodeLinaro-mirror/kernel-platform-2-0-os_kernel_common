/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PAGE_SIZE_COMPAT_H
#define __LINUX_PAGE_SIZE_COMPAT_H

/*
 * include/linux/page_size_compat.h
 *
 * Page Size Emulation
 *
 * Copyright (c) 2024, Google LLC.
 * Author: Kalesh Singh <kaleshsingh@goole.com>

 * Helper macros for page size emulation.
 *
 * The macors for use with the emulated page size are all
 * namespaced by the prefix '__'.
 */

#include <asm/page.h>

#include <linux/align.h>

#if defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT
extern unsigned __page_shift(void);

#define __PAGE_SHIFT 			__page_shift()
#else /* !defined(CONFIG_PAGE_SHIFT_COMPAT) || CONFIG_PAGE_SHIFT_COMPAT <= PAGE_SHIFT */
#define __PAGE_SHIFT 			PAGE_SHIFT
#endif /* defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT */

#define __PAGE_SIZE 			(_AC(1,UL) << __PAGE_SHIFT)
#define __PAGE_MASK 			(~(__PAGE_SIZE-1))

#define __PAGE_ALIGN(addr) 		ALIGN(addr, __PAGE_SIZE)
#define __PAGE_ALIGN_DOWN(addr)	ALIGN_DOWN(addr, __PAGE_SIZE)
#define __PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), __PAGE_SIZE)

#define __offset_in_page(p)		((unsigned long)(p) & ~__PAGE_MASK)

#endif /* __LINUX_PAGE_SIZE_COMPAT_H */

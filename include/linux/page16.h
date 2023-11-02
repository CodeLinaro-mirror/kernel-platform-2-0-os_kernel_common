/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PAGE16_H
#define __LINUX_PAGE16_H

/*
 * include/linux/page16.h
 *
 * Written by kaleshsingh
 *
 * Helper macros for x86 16K page size emulation.
 *
 * The macors for use with the emulated page size are all
 * namespaced by the prefix '__'.
 */

#include <linux/align.h>

#include <asm/page_types.h>

#ifdef CONFIG_EMULATE_16K_PAGE_SIZE
#define __PAGE_SHIFT		14
#else   /* !CONFIG_EMULATE_16K_PAGE_SIZE */
#define __PAGE_SHIFT		PAGE_SHIFT
#endif  /* CONFIG_EMULATE_16K_PAGE_SIZE */

#define __PAGE_SIZE		    (_AC(1,UL) << __PAGE_SHIFT)
#define __PAGE_MASK		    (~(__PAGE_SIZE-1))

#define __PAGE_ALIGN(addr)      ALIGN(addr, __PAGE_SIZE)
#define __PAGE_ALIGN_DOWN(addr) ALIGN_DOWN(addr, __PAGE_SIZE)
#define __PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), __PAGE_SIZE)

#define __offset_in_page(p)	((unsigned long)(p) & ~__PAGE_MASK)

#endif /* __LINUX_PAGE16_H */

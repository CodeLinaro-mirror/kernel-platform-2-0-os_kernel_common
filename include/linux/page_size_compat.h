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
#include <linux/mman.h>

#if defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT
extern unsigned __page_shift(void);

#define __PAGE_SHIFT 			__page_shift()

#define __VM_NO_COMPAT	0x00000800  /* VMA is exempt from emulated page align requirements */
#define __MAP_NO_COMPAT   0x8000

/* Combine the mmap "flags" argument into "vm_flags" add translation of the no-compat flag. */
static inline unsigned long __calc_vm_flag_bits(unsigned long flags)
{
    return calc_vm_flag_bits(flags) | _calc_vm_trans(flags, __MAP_NO_COMPAT,  __VM_NO_COMPAT );
}
#else /* !defined(CONFIG_PAGE_SHIFT_COMPAT) || CONFIG_PAGE_SHIFT_COMPAT <= PAGE_SHIFT */
#define __PAGE_SHIFT 			PAGE_SHIFT

#define __VM_NO_COMPAT	0x0  /* No-op VMA/mmap flags */
#define __MAP_NO_COMPAT   0x0

#define __calc_vm_flag_bits     calc_vm_flag_bits
#endif /* defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT */

#define __PAGE_SIZE 			(_AC(1,UL) << __PAGE_SHIFT)
#define __PAGE_MASK 			(~(__PAGE_SIZE-1))

#define __PAGE_ALIGN(addr) 		ALIGN(addr, __PAGE_SIZE)
#define __PAGE_ALIGN_DOWN(addr)	ALIGN_DOWN(addr, __PAGE_SIZE)
#define __PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), __PAGE_SIZE)

#define __offset_in_page(p)		((unsigned long)(p) & ~__PAGE_MASK)

#endif /* __LINUX_PAGE_SIZE_COMPAT_H */

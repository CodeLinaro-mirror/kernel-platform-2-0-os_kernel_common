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
#include <linux/mman.h>
#include <linux/sched.h>

#include <asm/page_types.h>

#ifdef  CONFIG_DEBUG_16K
#define LOG_16K(fmt, ...) \
	pr_debug("DEBUG 16K: [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__)

#define LOG_16K_IF(condition, fmt, ...) \
    do {                                \
        if (condition)                  \
            pr_debug("DEBUG 16K: [%i]: " fmt, task_pid_nr(current), ## __VA_ARGS__); \
    } while(0)

#else   /* !CONFIG_DEBUG_16K */
#define LOG_16K(fmt, ...) do {} while(0)
#define LOG_16K_IF(condition, fmt, ...) do {} while(0)
#endif  /* CONFIG_DEBUG_16K */

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

#define __VM_SPECIAL	0x00000800	/* VMA is exempt from emulated page align requirements */
#define __MAP_SPECIAL   0x8000		/* VMA is exempt from emulated page align requirements */

#ifdef CONFIG_EMULATE_16K_PAGE_SIZE
/*
 * Combine the mmap "flags" argument into "vm_flags" add translation
 * of the special flag.
 */
static inline unsigned long
__calc_vm_flag_bits(unsigned long flags)
{
    return calc_vm_flag_bits(flags) |
           _calc_vm_trans(flags, __MAP_SPECIAL,  __VM_SPECIAL );
}
#else   /* !CONFIG_EMULATE_16K_PAGE_SIZE */
static inline unsigned long
__calc_vm_flag_bits(unsigned long flags)
{
    return calc_vm_flag_bits(flags);
}
#endif  /* CONFIG_EMULATE_16K_PAGE_SIZE */

#endif /* __LINUX_PAGE16_H */

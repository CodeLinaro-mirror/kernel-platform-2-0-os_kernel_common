// SPDX-License-Identifier: GPL-2.0
/*
 * Page Size Emulation
 *
 * Copyright (c) 2024, Google LLC.
 * Author: Kalesh Singh <kaleshsingh@goole.com>
 */

#include <linux/page_size_compat.h>

#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/kstrtox.h>
#include <linux/mm.h>

#if defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT
DEFINE_STATIC_KEY_FALSE(page_size_compat);

unsigned __page_shift(void)
{
	if (static_branch_unlikely(&page_size_compat))
		return CONFIG_PAGE_SHIFT_COMPAT;
	else
		return PAGE_SHIFT;
}

static int __init early_page_size_compat(char *buf)
{
	int ret;
	bool bool_result;

	ret = kstrtobool(buf, &bool_result);
	if (ret)
		return ret;

	if (bool_result)
		static_branch_enable(&page_size_compat);
	else
		static_branch_disable(&page_size_compat);
	return 0;
}
early_param("page_size_compat", early_page_size_compat);

#define __MMAP_RND_BITS(x)      (x - (__PAGE_SHIFT - PAGE_SHIFT))

static int __init init_mmap_rnd_bits(void)
{
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
	mmap_rnd_bits_min = __MMAP_RND_BITS(CONFIG_ARCH_MMAP_RND_BITS_MIN);
	mmap_rnd_bits_max = __MMAP_RND_BITS(CONFIG_ARCH_MMAP_RND_BITS_MAX);
	mmap_rnd_bits = __MMAP_RND_BITS(CONFIG_ARCH_MMAP_RND_BITS);
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
	mmap_rnd_compat_bits_min = __MMAP_RND_BITS(CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN);
	mmap_rnd_compat_bits_max = __MMAP_RND_BITS(CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX);
	mmap_rnd_compat_bits = __MMAP_RND_BITS(CONFIG_ARCH_MMAP_RND_COMPAT_BITS);
#endif
	return 0;
}
core_initcall(init_mmap_rnd_bits);

#endif /* defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT */

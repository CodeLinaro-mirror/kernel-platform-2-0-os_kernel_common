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
#endif /* defined(CONFIG_PAGE_SHIFT_COMPAT) && CONFIG_PAGE_SHIFT_COMPAT > PAGE_SHIFT */

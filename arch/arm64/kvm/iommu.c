// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <linux/kvm_host.h>

static unsigned long dev_to_id(struct device *dev)
{
	/* Use the struct device pointer as a unique identifier. */
	return (unsigned long)dev;
}

int pkvm_iommu_driver_init(enum pkvm_iommu_driver_id id, void *data,
			   size_t data_size)
{
	return kvm_call_hyp_nvhe(__pkvm_iommu_driver_init, id, data, data_size);
}

int pkvm_iommu_register(struct device *dev, enum pkvm_iommu_driver_id drv_id,
			phys_addr_t pa, size_t size)
{
	void *mem = NULL;
	int ret;

	/*
	 * Hypcall to register the device. It will return -ENOMEM if it needs
	 * more memory. In that case allocate a page and retry (at most once).
	 * We assume that hyp never allocates more than a page per hypcall.
	 */
	while (true) {
		ret = kvm_call_hyp_nvhe(__pkvm_iommu_register, dev_to_id(dev),
					drv_id, pa, size, mem, PAGE_SIZE);
		if (ret == -ENOMEM) {
			/* Warn if hyp ran out of memory despite donating. */
			if (!WARN_ON_ONCE(mem)) {
				mem = (void *)__get_free_page(GFP_KERNEL);
				if (mem)
					continue;
			}
		}
		break;
	}
	return ret;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#include <kvm/device.h>

#include <nvhe/mem_protect.h>

struct pkvm_device *registered_devices;
unsigned long registered_devices_nr;

/*
 * This lock protects all devices in registered_devices when ctxt changes,
 * this is overlocking and can be improved. However, the device context
 * only changes at boot time and at teardown and in theory there shouldn't
 * be congestion on that path.
 * All changes/checks to MMIO state or IOMMU must be atomic with the ctxt
 * of the device.
 */
static DEFINE_HYP_SPINLOCK(device_spinlock);

int pkvm_init_devices(void)
{
	size_t dev_sz;
	int ret;

	if (!registered_devices_nr)
		return -ENODEV;
	registered_devices = kern_hyp_va(registered_devices);
	dev_sz = PAGE_ALIGN(size_mul(sizeof(struct pkvm_device),
				     registered_devices_nr));
	ret = __pkvm_host_donate_hyp(hyp_virt_to_phys(registered_devices) >> PAGE_SHIFT,
				     dev_sz >> PAGE_SHIFT);
	if (ret)
		registered_devices_nr = 0;

	return ret;
}

static struct pkvm_device *pkvm_get_device(u64 addr)
{
	struct pkvm_device *dev = NULL;
	struct pkvm_dev_resource *res;
	int i, j;

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		dev = &registered_devices[i];
		for (j = 0 ; j < dev->nr_resources; ++j) {
			res = &dev->resources[j];
			if ((addr >= res->base) && (addr < (res->base + res->size)))
				return dev;
		}
	}

	return NULL;
}

/*
 * Devices assigned to guest has to transition first to hypervisor,
 * this guarantees that there is a point of time that the device is
 * neither accessible from the host or the guest, so the hypervisor
 * can reset it and block it's IOOMU.
 * The host will donate the whole device first to the hypervisor
 * before the guest touches or requests any part of the device
 * and upon the first request or access the hypervisor will ensure
 * that the device is fully donated first.
 */
int pkvm_device_hyp_assign_mmio(u64 pfn)
{
	struct pkvm_device *dev = pkvm_get_device(hyp_pfn_to_phys(pfn));
	int ret;

	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);
	/* A VM already have this device, no take backs. */
	if (dev->ctxt) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = ___pkvm_host_donate_hyp_prot(pfn, 1, true, PAGE_HYP_DEVICE);

out_unlock:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

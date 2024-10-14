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

/*
 * Reclaim of MMIO happen under 2 conditions:
 * - VM is dying, in that case MMIO would eagerly reclaimed to host from VM
 *	 teardown context without host intervention.
 * - The VM was not launched or died before claiming the device, and it's is
 *   still considered as host device, but the MMIO was already donated to
 *   the hypervisor preparing for the VM to access it, in that case the host
 *   will use this function from an HVC to reclaim the MMIO from KVM/VFIO
 *   file release context or incase of failure at initialization.
 */
int pkvm_device_reclaim_mmio(u64 pfn)
{
	struct pkvm_device *dev = pkvm_get_device(hyp_pfn_to_phys(pfn));
	int ret;

	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);
	if (dev->ctxt) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = __pkvm_hyp_donate_host(pfn, 1);

out_unlock:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

bool pkvm_device_is_assignable(u64 pfn)
{
	return pkvm_get_device(hyp_pfn_to_phys(pfn)) != NULL;
}

static int __pkvm_device_assign(struct pkvm_device *dev, struct pkvm_hyp_vm *vm)
{
	int i;
	struct pkvm_dev_resource *res;
	int ret;

	hyp_assert_lock_held(&device_spinlock);

	for (i = 0 ; i < dev->nr_resources; ++i) {
		res = &dev->resources[i];
		ret = hyp_check_range_owned(res->base, res->size);
		if (ret)
			return ret;
	}

	dev->ctxt = vm;
	return 0;
}

/*
 * Atomically check that all the group is assigned to the hypervisor
 * and tag the devices in the group as owned by the VM.
 * This can't race with reclaim as it's protected by device_spinlock
 */
static int __pkvm_group_assign(u32 group_id, struct pkvm_hyp_vm *vm)
{
	int i;
	int ret = 0;

	hyp_assert_lock_held(&device_spinlock);

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		struct pkvm_device *dev = &registered_devices[i];

		if (dev->group_id != group_id)
			continue;
		if (dev->ctxt) {
			ret = -EPERM;
			break;
		}
		ret = __pkvm_device_assign(dev, vm);
		if (ret)
			break;
	}

	if (ret) {
		while (i--)
			registered_devices[i].ctxt = NULL;
	}
	return ret;
}


int pkvm_host_map_guest_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 pfn, u64 gfn)
{
	int ret = 0;
	struct pkvm_device *dev = pkvm_get_device(hyp_pfn_to_phys(pfn));
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);

	if (dev->ctxt == NULL) {
		/*
		 * First time the device is assigned to a guest, make sure the whole
		 * group is assigned to the hypervisor.
		 */
		ret = __pkvm_group_assign(dev->group_id, vm);
	} else if (dev->ctxt != vm) {
		ret = -EPERM;
	}

	if (ret)
		goto out_ret;

	ret = pkvm_hyp_donate_guest(hyp_vcpu, pfn, gfn, 1);

out_ret:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

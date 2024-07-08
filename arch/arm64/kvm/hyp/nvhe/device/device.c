// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#include <kvm/arm_hypercalls.h>
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

static int pkvm_device_reset(struct pkvm_device *dev)
{
	hyp_assert_lock_held(&device_spinlock);

	if (dev->reset_handler)
		return dev->reset_handler(dev);
	return 0;
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

	ret = pkvm_device_reset(dev);
	if (ret)
		return ret;

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

static int pkvm_get_device_pa(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa, u64 *pa, u64 *exit_code)
{
	struct kvm_hyp_req *req;
	int ret;
	u64 pte;
	u32 level;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret || !kvm_pte_valid(pte)) {
		/* Page not mapped, create a request*/
		req = pkvm_hyp_req_reserve(hyp_vcpu, KVM_HYP_REQ_TYPE_MAP);
		if (!req)
			return -ENOMEM;

		req->map.guest_ipa = ipa;
		req->map.size = PAGE_SIZE;
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		/* Repeat next time. */
		write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 4, SYS_ELR);
		return -ENODEV;
	}

	*pa = kvm_pte_to_phys(pte);
	*pa |= (ipa & kvm_granule_size(level) - 1) & PAGE_MASK;
	return 0;
}

bool pkvm_device_request_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	int i, j, ret;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct pkvm_dev_resource *res;
	struct pkvm_device *dev;
	u64 ipa = smccc_get_arg1(vcpu);
	u64 token;

	ret = pkvm_get_device_pa(hyp_vcpu, ipa, &token, exit_code);
	if (ret)
		return false;

	hyp_spin_lock(&device_spinlock);
	for (i = 0 ; i < registered_devices_nr ; ++i) {
		dev = &registered_devices[i];
		if (dev->ctxt != vm)
			continue;

		for (j = 0 ; j < dev->nr_resources; ++j) {
			res = &dev->resources[j];
			if ((token >= res->base) && (token + PAGE_SIZE <= res->base + res->size)) {
				smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, token, 0, 0);
				goto out_ret;
			}
		}
	}

	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
out_ret:
	hyp_spin_unlock(&device_spinlock);
	return true;
}

static void pkvm_devices_reclaim_device(struct pkvm_device *dev)
{
	int i;

	for (i = 0 ; i < dev->nr_resources ; ++i) {
		struct pkvm_dev_resource *res = &dev->resources[i];

		hyp_spin_lock(&host_mmu.lock);
		host_stage2_set_owner_locked(res->base, res->size, PKVM_ID_HOST);
		hyp_spin_unlock(&host_mmu.lock);
	}
}

void pkvm_devices_teardown(struct pkvm_hyp_vm *vm)
{
	int i;

	hyp_spin_lock(&device_spinlock);
	for (i = 0 ; i < registered_devices_nr ; ++i) {
		struct pkvm_device *dev = &registered_devices[i];

		if (dev->ctxt != vm)
			continue;
		WARN_ON(pkvm_device_reset(dev));
		dev->ctxt = NULL;
		pkvm_devices_reclaim_device(dev);
	}
	hyp_spin_unlock(&device_spinlock);
}

static struct pkvm_device *pkvm_get_device_by_iommu(u64 id, u64 endpoint)
{
	struct pkvm_device *dev = NULL;
	struct pkvm_dev_iommu *iommu;
	int i, j;

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		dev = &registered_devices[i];
		for (j = 0 ; j < dev->nr_iommus; ++j) {
			iommu = &dev->iommus[j];
			if ((id == iommu->id) && (endpoint == iommu->endpoint))
				return dev;
		}
	}

	return NULL;
}

/*
 * Check if the host or a VM allowed to access a device and keep the device lock
 * held to avoid races with ctxt changes that includes blocking the device.
 * In case of 0 returned, the caller is expected to call pkvm_devices_iommu_unlock()
 */
int pkvm_devices_iommu_lock(u64 id, u64 endpoint, struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_device *dev = pkvm_get_device_by_iommu(id, endpoint);
	struct pkvm_hyp_vm *vm = NULL;

	/* Non assignable device, only allowed to host */
	if (!dev) {
		if (vcpu)
			return -EPERM;
		else
			return 0;
	}

	if (vcpu)
		vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);

	hyp_spin_lock(&device_spinlock);
	if (dev->ctxt == vm)
		return 0;
	hyp_spin_unlock(&device_spinlock);
	return -EPERM;
}

void pkvm_devices_iommu_unlock(u64 id, u64 endpoint)
{
	struct pkvm_device *dev = pkvm_get_device_by_iommu(id, endpoint);

	if (dev)
		hyp_spin_unlock(&device_spinlock);
}

int pkvm_device_register_reset(u64 phys, int (*cb)(struct pkvm_device *))
{
	struct pkvm_device *dev;

	dev = pkvm_get_device(phys);
	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);
	/* No reason to prevent changing the callback. */
	dev->reset_handler = cb;
	hyp_spin_unlock(&device_spinlock);

	return 0;
}

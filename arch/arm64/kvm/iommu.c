// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#include <asm/kvm_mmu.h>
#include <linux/kvm_host.h>
#include <kvm/iommu.h>

struct kvm_iommu_driver *iommu_driver;
extern struct kvm_iommu_ops *kvm_nvhe_sym(kvm_iommu_ops);

int kvm_iommu_register_driver(struct kvm_iommu_driver *kern_ops)
{
	BUG_ON(!kern_ops);

	/*
	 * Paired with smp_load_acquire(&iommu_driver)
	 * Ensure memory stores happening during a driver
	 * init are observed before executing kvm iommu callbacks.
	 */
	return cmpxchg_release(&iommu_driver, NULL, kern_ops) ? -EBUSY : 0;
}
EXPORT_SYMBOL(kvm_iommu_register_driver);

int kvm_iommu_init_hyp(struct kvm_iommu_ops *hyp_ops,
		       struct kvm_hyp_memcache *atomic_mc,
		       unsigned long init_arg)
{
	BUG_ON(!hyp_ops);

	return kvm_call_hyp_nvhe(__pkvm_iommu_init, hyp_ops,
				 atomic_mc->head, atomic_mc->nr_pages, init_arg);
}
EXPORT_SYMBOL(kvm_iommu_init_hyp);

int kvm_iommu_init_driver(void)
{
	if (!smp_load_acquire(&iommu_driver) || !iommu_driver->get_iommu_id) {
		kvm_err("pKVM enabled with no IOMMU driver, do not run confidential" \
			 " workloads in virtual machines\n");
		return -ENODEV;
	}
	/*
	 * init_driver is optional as the driver already registered it self.
	 * This call mainly notify the driver we are about to drop privilege.
	 */
	if (!iommu_driver->init_driver)
		return 0;
	kvm_hyp_iommu_domains = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
				get_order(KVM_IOMMU_DOMAINS_ROOT_SIZE));
	kvm_hyp_iommu_domains = kern_hyp_va(kvm_hyp_iommu_domains);
	if (!kvm_hyp_iommu_domains) {
		kvm_err("No enough mem for IOMMU domains");
		return -ENOMEM;
	}

	return iommu_driver->init_driver();
}

void kvm_iommu_remove_driver(void)
{
	if (smp_load_acquire(&iommu_driver))
		iommu_driver->remove_driver();
}

pkvm_handle_t kvm_get_iommu_id(struct device *dev)
{
	return iommu_driver->get_iommu_id(dev);
}

pkvm_handle_t kvm_get_iommu_id_by_of(struct device_node *np)
{
	if (!smp_load_acquire(&iommu_driver) || !iommu_driver->get_iommu_id_by_of)
		return 0;

	return iommu_driver->get_iommu_id_by_of(np);
}

int pkvm_iommu_suspend(struct device *dev)
{
	int device_id = kvm_get_iommu_id(dev);

	return kvm_call_hyp_nvhe(__pkvm_host_hvc_pd, device_id, 0);
}
EXPORT_SYMBOL(pkvm_iommu_suspend);

int pkvm_iommu_resume(struct device *dev)
{
	int device_id = kvm_get_iommu_id(dev);

	return kvm_call_hyp_nvhe(__pkvm_host_hvc_pd, device_id, 1);
}
EXPORT_SYMBOL(pkvm_iommu_resume);

int kvm_iommu_device_num_ids(struct device *dev)
{
	if (iommu_driver->get_device_iommu_num_ids)
		return iommu_driver->get_device_iommu_num_ids(dev);
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_iommu_device_num_ids);

int kvm_iommu_device_id(struct device *dev, u32 idx,
			pkvm_handle_t *out_iommu, u32 *out_sid)
{
	if (iommu_driver->get_device_iommu_id)
		return iommu_driver->get_device_iommu_id(dev, idx, out_iommu, out_sid);
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(kvm_iommu_device_id);

int kvm_iommu_guest_alloc_mc(struct kvm_hyp_memcache *mc, u32 pgsize, u32 nr_pages)
{
	u8 order = get_order(pgsize);

	/* Driver might have dedicated allocator especially if it needs large pages. */
	if (iommu_driver->guest_alloc && iommu_driver->guest_free)
		return __topup_hyp_memcache(mc, nr_pages, iommu_driver->guest_alloc,
					    kvm_host_pa, 0, order);

	return topup_hyp_memcache(mc, nr_pages, order);
}

void kvm_iommu_guest_free_mc(struct kvm_hyp_memcache *mc)
{
	if (iommu_driver->guest_alloc && iommu_driver->guest_free)
		__free_hyp_memcache(mc, iommu_driver->guest_free,
				    kvm_host_va, 0);
	else
		free_hyp_memcache(mc);
}

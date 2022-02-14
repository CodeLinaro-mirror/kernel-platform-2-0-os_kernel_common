// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>

#include <nvhe/iommu.h>
#include <nvhe/mm.h>

enum {
	IOMMU_DRIVER_NOT_READY = 0,
	IOMMU_DRIVER_INITIALIZING,
	IOMMU_DRIVER_READY,
};

struct pkvm_iommu_driver {
	const struct pkvm_iommu_ops *ops;
	atomic_t state;
};

static struct pkvm_iommu_driver iommu_drivers[PKVM_IOMMU_NR_DRIVERS];

static LIST_HEAD(iommu_list);
static DEFINE_HYP_SPINLOCK(iommu_lock);

static void host_lock_component(void)
{
	hyp_spin_lock(&host_kvm.lock);
}

static void host_unlock_component(void)
{
	hyp_spin_unlock(&host_kvm.lock);
}

static void iommu_lock_component(void)
{
	/* Enforce lock ordering: host_kvm.lock >> iommu_list_lock */
	hyp_assert_lock_held(&host_kvm.lock);
	hyp_spin_lock(&iommu_lock);
}

static void iommu_unlock_component(void)
{
	hyp_spin_unlock(&iommu_lock);
}

/*
 * Find IOMMU driver by its ID. The input ID is treated as unstrusted
 * and is properly validated.
 */
static inline struct pkvm_iommu_driver *get_driver(enum pkvm_iommu_driver_id id)
{
	size_t index = (size_t)id;

	if (index >= ARRAY_SIZE(iommu_drivers))
		return NULL;

	return &iommu_drivers[index];
}

static const struct pkvm_iommu_ops *get_driver_ops(enum pkvm_iommu_driver_id id)
{
	switch (id) {
	default:
		return NULL;
	}
}

static inline bool driver_acquire_init(struct pkvm_iommu_driver *drv)
{
	return atomic_cmpxchg_acquire(&drv->state, IOMMU_DRIVER_NOT_READY,
				      IOMMU_DRIVER_INITIALIZING)
			== IOMMU_DRIVER_NOT_READY;
}

static inline void driver_release_init(struct pkvm_iommu_driver *drv,
				       bool success)
{
	atomic_set_release(&drv->state, success ? IOMMU_DRIVER_READY
						: IOMMU_DRIVER_NOT_READY);
}

static inline bool is_driver_ready(struct pkvm_iommu_driver *drv)
{
	return atomic_read(&drv->state) == IOMMU_DRIVER_READY;
}

/* Global memory pool for allocating IOMMU list entry structs. */
static inline struct pkvm_iommu *
alloc_iommu_list_entry(size_t extra_size, void *mem, size_t mem_size)
{
	static void *pool;
	static size_t remaining;
	static DEFINE_HYP_SPINLOCK(lock);
	size_t size = sizeof(struct pkvm_iommu) + extra_size;
	void *ptr;

	size = ALIGN(size, sizeof(unsigned long));

	hyp_spin_lock(&lock);

	/*
	 * If new memory is being provided, replace the existing pool with it.
	 * Any remaining memory in the pool is discarded.
	 */
	if (mem && mem_size) {
		pool = mem;
		remaining = mem_size;
	}

	if (size <= remaining) {
		ptr = pool;
		pool += size;
		remaining -= size;
	} else {
		ptr = NULL;
	}

	hyp_spin_unlock(&lock);
	return ptr;
}

static bool is_overlap(phys_addr_t r1_start, size_t r1_size,
		       phys_addr_t r2_start, size_t r2_size)
{
	phys_addr_t r1_end = r1_start + r1_size;
	phys_addr_t r2_end = r2_start + r2_size;

	return (r1_start < r2_end) && (r2_start < r1_end);
}

static bool is_mmio_range(phys_addr_t base, size_t size)
{
	struct memblock_region *reg;
	phys_addr_t limit = BIT(host_kvm.pgt.ia_bits);
	size_t i;

	/* Check against limits of host IPA space. */
	if ((base >= limit) || !size || (size > limit - base))
		return false;

	for (i = 0; i < hyp_memblock_nr; i++) {
		reg = &hyp_memory[i];
		if (is_overlap(base, size, reg->base, reg->size))
			return false;
	}
	return true;
}

static int __snapshot_host_stage2(u64 start, u64 end, u32 level,
				  kvm_pte_t *ptep,
				  enum kvm_pgtable_walk_flags flags,
				  void * const arg)
{
	struct pkvm_iommu_driver * const drv = arg;
	enum kvm_pgtable_prot prot;
	kvm_pte_t pte = *ptep;

	/*
	 * Valid stage-2 entries are created lazily, invalid ones eagerly.
	 * Note: In the future we may need to check if [start,end) is MMIO.
	 */
	prot = (!pte || kvm_pte_valid(pte)) ? PKVM_HOST_MEM_PROT : 0;

	drv->ops->host_stage2_idmap_prepare(start, end, prot);
	return 0;
}

static int snapshot_host_stage2(struct pkvm_iommu_driver * const drv)
{
	struct kvm_pgtable_walker walker = {
		.cb	= __snapshot_host_stage2,
		.arg	= drv,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};
	struct kvm_pgtable *pgt = &host_kvm.pgt;

	if (!drv->ops->host_stage2_idmap_prepare)
		return 0;

	return kvm_pgtable_walk(pgt, 0, BIT(pgt->ia_bits), &walker);
}

static bool validate_against_existing_iommus(struct pkvm_iommu *dev)
{
	struct pkvm_iommu *other;

	hyp_assert_lock_held(&iommu_list_lock);

	list_for_each_entry(other, &iommu_list, list) {
		/* Device ID must be unique. */
		if (dev->id == other->id)
			return false;

		/* MMIO regions must not overlap. */
		if (is_overlap(dev->pa, dev->size, other->pa, other->size))
			return false;
	}
	return true;
}

static struct pkvm_iommu *find_iommu_by_id(unsigned long id)
{
	struct pkvm_iommu *dev, *res = NULL;

	iommu_lock_component();
	list_for_each_entry(dev, &iommu_list, list) {
		if (dev->id == id) {
			res = dev;
			break;
		}
	}
	iommu_unlock_component();
	return res;
}

static struct pkvm_iommu *find_iommu_by_pa(phys_addr_t pa)
{
	struct pkvm_iommu *dev, *res = NULL;

	iommu_lock_component();
	list_for_each_entry(dev, &iommu_list, list) {
		if (dev->pa <= pa && pa < dev->pa + dev->size) {
			res = dev;
			break;
		}
	}
	iommu_unlock_component();
	return res;
}

/*
 * Initialize EL2 IOMMU driver.
 *
 * This is a common hypercall for driver initialization. Driver-specific
 * arguments are passed in a shared memory buffer. The driver is expected to
 * initialize it's page-table bookkeeping.
 */
int __pkvm_iommu_driver_init(enum pkvm_iommu_driver_id id, void *data,
			     size_t szdata)
{
	struct pkvm_iommu_driver *drv;
	const struct pkvm_iommu_ops *ops;
	int ret = 0;

	data = kern_hyp_va(data);

	drv = get_driver(id);
	ops = get_driver_ops(id);
	if (!drv || !ops)
		return -EINVAL;

	if (!driver_acquire_init(drv))
		return -EBUSY;

	drv->ops = ops;

	/* This can change stage-2 mappings. */
	if (ops->init) {
		ret = hyp_pin_shared_mem(data, data + szdata);
		if (!ret) {
			ret = ops->init(data, szdata);
			hyp_unpin_shared_mem(data, data + szdata);
		}
		if (ret)
			goto out;
	}

	/*
	 * Walk host stage-2 and pass current mappings to the driver. Start
	 * accepting host stage-2 updates as soon as the host lock is released.
	 */
	host_lock_component();
	ret = snapshot_host_stage2(drv);
	if (!ret)
		driver_release_init(drv, /*success=*/true);
	host_unlock_component();

out:
	if (ret)
		driver_release_init(drv, /*success=*/false);
	return ret;
}

int __pkvm_iommu_register(unsigned long dev_id,
			  enum pkvm_iommu_driver_id drv_id,
			  phys_addr_t dev_pa, size_t dev_size,
			  void *kern_mem_va, size_t mem_size)
{
	struct pkvm_iommu *dev = NULL;
	struct pkvm_iommu_driver *drv;
	void *mem_va = NULL;
	unsigned long addr;
	int ret = 0;

	drv = get_driver(drv_id);
	if (!drv || !is_driver_ready(drv))
		return -ENOENT;

	if (!PAGE_ALIGNED(dev_pa) || !PAGE_ALIGNED(dev_size))
		return -EINVAL;

	if (!is_mmio_range(dev_pa, dev_size))
		return -EINVAL;

	if (drv->ops->validate) {
		ret = drv->ops->validate(dev_pa, dev_size);
		if (ret)
			return ret;
	}

	/*
	 * Accept memory donation if the host is providing new memory.
	 * Note: We do not return the memory even if there is an error later.
	 */
	if (kern_mem_va && mem_size) {
		mem_va = kern_hyp_va(kern_mem_va);

		if (!PAGE_ALIGNED(mem_va) || !PAGE_ALIGNED(mem_size))
			return -EINVAL;

		ret = __pkvm_host_donate_hyp(hyp_phys_to_pfn(__hyp_pa(mem_va)),
					     mem_size >> PAGE_SHIFT);
		if (ret)
			return ret;
	}

	/* Allocate memory for the new device entry. */
	dev = alloc_iommu_list_entry(drv->ops->dev_data_size, mem_va, mem_size);
	if (!dev)
		return -ENOMEM;

	/* Create EL2 mapping for the device. */
	addr = __pkvm_create_private_mapping(dev_pa, dev_size, PAGE_HYP_DEVICE);
	if (IS_ERR((void *)addr))
		return PTR_ERR((void *)addr);

	/* Populate the new device entry. */
	*dev = (struct pkvm_iommu){
		.id = dev_id,
		.ops = drv->ops,
		.pa = dev_pa,
		.va = (void __iomem *)addr,
		.size = dev_size,
	};

	/* Take the host_kvm lock to block host stage-2 changes. */
	host_lock_component();

	/* Unmap the device's MMIO range from host stage-2. */
	ret = host_stage2_unmap_dev_locked(dev_pa, dev_size);
	if (ret)
		goto out;

	/*
	 * Insert device into the list of IOMMU devices. This will block
	 * attempts to map the device's MMIO range in the DABT handler.
	 */
	iommu_lock_component();
	if (validate_against_existing_iommus(dev))
		list_add_tail(&dev->list, &iommu_list);
	else
		ret = -EBUSY;
	iommu_unlock_component();

out:
	host_unlock_component();
	return ret;
}

int __pkvm_iommu_pm_notify(unsigned long dev_id, enum pkvm_iommu_pm_event event)
{
	struct pkvm_iommu *dev;
	int ret;

	dev = find_iommu_by_id(dev_id);
	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&dev->lock);
	switch (event) {
	case PKVM_IOMMU_PM_SUSPEND:
		ret = dev->ops->suspend ? dev->ops->suspend(dev) : 0;
		dev->powered = !!ret;
		break;
	case PKVM_IOMMU_PM_RESUME:
		ret = dev->ops->resume ? dev->ops->resume(dev) : 0;
		dev->powered = !ret;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	hyp_spin_unlock(&dev->lock);
	return ret;
}

/*
 * Check host memory access against IOMMUs' MMIO regions.
 * Returns -EPERM if the address is within the bounds of a registered device.
 * Otherwise returns zero and adjusts boundaries of the new mapping to avoid
 * MMIO regions of registered IOMMUs.
 */
int pkvm_iommu_host_stage2_adjust_range(phys_addr_t addr, phys_addr_t *start,
					phys_addr_t *end)
{
	struct pkvm_iommu *dev;
	phys_addr_t new_start = *start;
	phys_addr_t new_end = *end;
	phys_addr_t dev_start, dev_end;
	int ret = 0;

	iommu_lock_component();
	list_for_each_entry(dev, &iommu_list, list) {
		dev_start = dev->pa;
		dev_end = dev_start + dev->size;

		if (addr < dev_start) {
			new_end = min(new_end, dev_start);
		} else if (addr >= dev_end) {
			new_start = max(new_start, dev_end);
		} else {
			ret = -EPERM;
			break;
		}
	}
	iommu_unlock_component();

	if (!ret) {
		*start = new_start;
		*end = new_end;
	}
	return ret;
}

bool pkvm_iommu_host_dabt_handler(struct kvm_cpu_context *host_ctxt, u32 esr,
				  phys_addr_t fault_pa)
{
	struct pkvm_iommu *dev;
	bool ret;

	dev = find_iommu_by_pa(fault_pa);
	if (!dev || !dev->ops->host_dabt_handler)
		return false;

	hyp_spin_lock(&dev->lock);
	ret = dev->powered && dev->ops->host_dabt_handler(dev, host_ctxt, esr,
							  fault_pa - dev->pa);
	hyp_spin_unlock(&dev->lock);
	return ret;
}

void pkvm_iommu_host_stage2_idmap(phys_addr_t start, phys_addr_t end,
				  enum kvm_pgtable_prot prot)
{
	struct pkvm_iommu_driver *drv;
	struct pkvm_iommu *dev;
	size_t i;

	hyp_assert_lock_held(&host_kvm.lock);

	for (i = 0; i < ARRAY_SIZE(iommu_drivers); i++) {
		drv = get_driver(i);
		if (!drv || !is_driver_ready(drv))
			continue;

		if (drv->ops->host_stage2_idmap_prepare)
			drv->ops->host_stage2_idmap_prepare(start, end, prot);

		if (!drv->ops->host_stage2_idmap_apply)
			continue;

		iommu_lock_component();
		list_for_each_entry(dev, &iommu_list, list) {
			if (dev->ops != drv->ops)
				continue;

			hyp_spin_lock(&dev->lock);
			if (dev->powered)
				drv->ops->host_stage2_idmap_apply(dev, start, end);
			hyp_spin_unlock(&dev->lock);
		}
		iommu_unlock_component();
	}
}

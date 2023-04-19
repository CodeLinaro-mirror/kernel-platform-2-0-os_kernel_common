// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#include <kvm/arm_hypercalls.h>
#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>
#include <nvhe/pviommu.h>
#include <nvhe/pviommu-host.h>

#include <linux/kvm_host.h>
#include <nvhe/pkvm.h>

static DEFINE_HYP_SPINLOCK(pviommu_guest_domain_lock);

#define KVM_IOMMU_MAX_GUEST_DOMAINS		(KVM_IOMMU_MAX_DOMAINS >> 1)
static unsigned long guest_domains[KVM_IOMMU_MAX_GUEST_DOMAINS / BITS_PER_LONG];

/*
 * Guests doens't have separate domain space as the host, but they share the upper half
 * of the domain space, so they would ask for a domain and get a domain_id as a return.
 * This will ONLY looks in the guest space and should be protected by the caller, so no
 * looks is needed here.
 * This is a rare operation for guests, so bruteforcing the domain space should be fine
 * for now, however we can improve this by having a hint for last allocated domain_id or
 * use a pseudo-random number.
 */
static int pkvm_guest_iommu_alloc_id(void)
{
	int i;

	for (i = 0 ; i < ARRAY_SIZE(guest_domains) ; ++i) {
		if (guest_domains[i] != ~0UL)
			return ffz(guest_domains[i]) + (KVM_IOMMU_MAX_DOMAINS >> 1);
	}

	return -EBUSY;
}

static void pkvm_guest_iommu_free_id(int domain_id)
{
	domain_id -= (KVM_IOMMU_MAX_DOMAINS >> 1);
	if (WARN_ON(domain_id < 0) || (domain_id >= KVM_IOMMU_MAX_GUEST_DOMAINS))
		return;

	guest_domains[domain_id / BITS_PER_LONG] &= ~(1UL << (domain_id % BITS_PER_LONG));
}

/*
 * Some IOMMU ops have no error return (map/ummap) and return the number of mapped,
 * bytes. However, we need to a way to check if memory was needed, so we rely o
 * requestes issued from the vcpu to check that.
 */
bool __need_req(struct kvm_vcpu *vcpu)
{
	struct kvm_hyp_req *hyp_req = vcpu->arch.hyp_reqs;

	return hyp_req->type != KVM_HYP_LAST_REQ;
}

static int pkvm_get_guest_pa(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa, u64 ipa_size,
			     u64 *pa, u64 *exit_code)
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
		req->map.size = ipa_size;
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return -ENODEV;
	}

	*pa = kvm_pte_to_phys(pte);
	*pa |= (ipa & kvm_granule_size(level) - 1) & PAGE_MASK;

	return 0;
}

static bool prev_guest_req(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	u64 elr;

	if (__need_req(vcpu)) {
		elr = read_sysreg(elr_el2);
		elr -= 4;
		write_sysreg(elr, elr_el2);
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return true;
	}
	return false;
}

static int __smccc_prot_linux(u64 prot)
{
	int iommu_prot = 0;

	if (prot & ARM_SMCCC_KVM_PVIOMMU_READ)
		iommu_prot |= IOMMU_READ;
	if (prot & ARM_SMCCC_KVM_PVIOMMU_WRITE)
		iommu_prot |= IOMMU_WRITE;
	if (prot & ARM_SMCCC_KVM_PVIOMMU_CACHE)
		iommu_prot |= IOMMU_CACHE;
	if (prot & ARM_SMCCC_KVM_PVIOMMU_NOEXEC)
		iommu_prot |= IOMMU_NOEXEC;
	if (prot & ARM_SMCCC_KVM_PVIOMMU_MMIO)
		iommu_prot |= IOMMU_MMIO;
	if (prot & ARM_SMCCC_KVM_PVIOMMU_PRIV)
		iommu_prot |= IOMMU_PRIV;

	return iommu_prot;
}

static bool pkvm_guest_iommu_map(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	size_t mapped, total_mapped = 0;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 domain = smccc_get_arg1(vcpu);
	u64 iova = smccc_get_arg2(vcpu);
	u64 ipa = smccc_get_arg3(vcpu);
	u64 pgsize = smccc_get_arg4(vcpu);
	u64 pgcount = smccc_get_arg5(vcpu);
	u64 prot = smccc_get_arg6(vcpu);
	u64 paddr;
	int ret;
	u64 smccc_ret = SMCCC_RET_SUCCESS;

	/* In theory we can support larger page sizes, see pkvm_guest_iommu_get_feature(). */
	if (pgsize != PAGE_SIZE) {
		smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
		return true;
	}

	/* See comment below after kvm_iommu_map_pages(). */
	if (prev_guest_req(vcpu, exit_code))
		return false;

	while (pgcount--) {
		ret = pkvm_get_guest_pa(hyp_vcpu, ipa, pgsize * pgcount, &paddr, exit_code);
		if (ret)
			break;
		mapped = kvm_iommu_map_pages(domain, iova, paddr,
					     pgsize, 1, __smccc_prot_linux(prot));
		/*
		 * In case we need memory, we return the current mapped pages, and on the next
		 * HVC we would return directly to host to fulfill the request as the current
		 * context can't be saved.
		 * We rely on requests only cleared with exit reason ARM_EXCEPTION_HYP_REQ, as
		 * there it is possible the guest can exit by other reasons as ARM_EXCEPTION_IRQ
		 * however in this case the request should be retained in the next time we run
		 * the vcpu.
		 */
		if (!mapped) {
			if (!__need_req(vcpu))
				smccc_ret = SMCCC_RET_INVALID_PARAMETER;
			break;
		}

		ipa += pgsize;
		iova += pgsize;
		total_mapped += pgsize;
	}

	smccc_set_retval(vcpu, smccc_ret, total_mapped, 0, 0);
	return true;
}

static bool pkvm_guest_iommu_unmap(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 domain = smccc_get_arg1(vcpu);
	u64 iova = smccc_get_arg2(vcpu);
	u64 pgsize = smccc_get_arg3(vcpu);
	u64 pgcount = smccc_get_arg4(vcpu);
	size_t unmapped, size = pgsize * pgcount;
	unsigned long ret = SMCCC_RET_SUCCESS;

	if (pgsize != PAGE_SIZE) {
		smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
		return true;
	}

	/* See comment in pkvm_guest_iommu_map(). */
	if (prev_guest_req(vcpu, exit_code))
		return false;

	unmapped = kvm_iommu_unmap_pages(domain, iova, pgsize, pgcount);
	if (unmapped < size) {
		if (!__need_req(vcpu))
			ret = SMCCC_RET_INVALID_PARAMETER;
	}

	smccc_set_retval(vcpu, ret, unmapped, 0, 0);
	return true;
}

static void pkvm_pviommu_hyp_req(u64 *exit_code)
{
	u64 elr;

	elr = read_sysreg(elr_el2);
	elr -= 4;
	write_sysreg(elr, elr_el2);
	*exit_code = ARM_EXCEPTION_HYP_REQ;
}

static bool pkvm_guest_iommu_attach_dev(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	int ret;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 iommu_id = smccc_get_arg1(vcpu);
	u64 sid = smccc_get_arg2(vcpu);
	u64 pasid = smccc_get_arg3(vcpu);
	u64 domain_id = smccc_get_arg4(vcpu);
	u64 pasid_bits = smccc_get_arg5(vcpu);
	struct pviommu_route route;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	ret = pkvm_pviommu_route(vm, iommu_id, sid, &route);
	if (ret)
		goto out_ret;
	iommu_id = route.iommu;
	sid = route.sid;

	ret = kvm_iommu_attach_dev(iommu_id, domain_id, sid, pasid, pasid_bits);
	if (ret == -ENOMEM) {
		pkvm_pviommu_hyp_req(exit_code);
		return false;
	}

out_ret:
	smccc_set_retval(vcpu, ret ?  SMCCC_RET_INVALID_PARAMETER : SMCCC_RET_SUCCESS,
			 0, 0, 0);
	return true;
}

static bool pkvm_guest_iommu_detach_dev(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	int ret;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 iommu = smccc_get_arg1(vcpu);
	u64 sid = smccc_get_arg2(vcpu);
	u64 pasid = smccc_get_arg3(vcpu);
	u64 domain = smccc_get_arg4(vcpu);
	struct pviommu_route route;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	ret = pkvm_pviommu_route(vm, iommu, sid, &route);
	if (ret)
		goto out_ret;
	iommu = route.iommu;
	sid = route.sid;

	ret = kvm_iommu_detach_dev(iommu, domain, sid, pasid);

out_ret:
	smccc_set_retval(vcpu, ret ?  SMCCC_RET_INVALID_PARAMETER : SMCCC_RET_SUCCESS,
			 0, 0, 0);
	return true;
}

static bool pkvm_guest_iommu_version(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;

	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, PVIOMMU_VERSION, 0, 0);
	return true;
}

static bool pkvm_guest_iommu_get_feature(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	/* Arg1 reserved for the iommu currently unused. */
	unsigned long req_feature = smccc_get_arg2(&hyp_vcpu->vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;

	switch (req_feature) {
	case PVIOMMU_REQUEST_FEATURE_PGSZ_BITMAP:
		/*
		 * We only advertise page size for IOMMU bit map and not the actual page size
		 * bit map as the guest memory might be contiguous in IPA space but not in physical
		 * space.
		 */
		smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, PAGE_SIZE, 0, 0);
		return true;
	}

	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pkvm_guest_iommu_alloc_domain(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	int ret;
	int domain_id = 0;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;

	/*
	 * As guest domains share same ID space, this function must be protected by
	 * a lock, using the common for IOMMU would be too much for this operation
	 * so we require the caller to protect kvm_iommu_alloc_guest_domain for guest
	 * access.
	 */
	hyp_spin_lock(&pviommu_guest_domain_lock);
	domain_id = pkvm_guest_iommu_alloc_id();
	if (domain_id < 0) {
		hyp_spin_unlock(&pviommu_guest_domain_lock);
		goto out_inval;
	}

	ret = kvm_iommu_alloc_domain(domain_id, KVM_IOMMU_DOMAIN_ANY_TYPE);
	if (ret == -ENOMEM) {
		pkvm_guest_iommu_free_id(domain_id);
		hyp_spin_unlock(&pviommu_guest_domain_lock);
		pkvm_pviommu_hyp_req(exit_code);
		return false;
	} else if (ret) {
		pkvm_guest_iommu_free_id(domain_id);
		goto out_inval;
	}

	hyp_spin_unlock(&pviommu_guest_domain_lock);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, domain_id, 0, 0);
	return true;

out_inval:
	hyp_spin_unlock(&pviommu_guest_domain_lock);
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pkvm_guest_iommu_free_domain(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	int ret;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 domain_id = smccc_get_arg1(vcpu);

	hyp_spin_lock(&pviommu_guest_domain_lock);
	ret = kvm_iommu_free_domain(domain_id);
	if (!ret)
		pkvm_guest_iommu_free_id(domain_id);
	hyp_spin_unlock(&pviommu_guest_domain_lock);

	smccc_set_retval(vcpu, ret ?  SMCCC_RET_INVALID_PARAMETER : SMCCC_RET_SUCCESS,
			 0, 0, 0);
	return true;
}

bool kvm_handle_pviommu_hvc(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	u32 fn = smccc_get_function(vcpu);
	struct pkvm_hyp_vcpu *hyp_vcpu = container_of(vcpu, struct pkvm_hyp_vcpu, vcpu);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	/*
	 * Eagerly fill the vm iommu pool to avoid deadlocks from donation path while
	 * doing IOMMU operations.
	 */
	refill_hyp_pool(&vm->iommu_pool, &hyp_vcpu->host_vcpu->arch.iommu_mc);
	switch (fn) {
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_MAP_FUNC_ID:
		return pkvm_guest_iommu_map(hyp_vcpu, exit_code);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_UNMAP_FUNC_ID:
		return pkvm_guest_iommu_unmap(hyp_vcpu, exit_code);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_ATTACH_DEV_FUNC_ID:
		return pkvm_guest_iommu_attach_dev(hyp_vcpu, exit_code);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_DETACH_DEV_FUNC_ID:
		return pkvm_guest_iommu_detach_dev(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_VERSION_FUNC_ID:
		return pkvm_guest_iommu_version(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_GET_FEATURE_FUNC_ID:
		return pkvm_guest_iommu_get_feature(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_ALLOC_DOMAIN_FUNC_ID:
		return pkvm_guest_iommu_alloc_domain(hyp_vcpu, exit_code);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_FREE_DOMAIN_FUNC_ID:
		return pkvm_guest_iommu_free_domain(hyp_vcpu);
	}

	return false;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#include <kvm/arm_hypercalls.h>
#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>
#include <nvhe/pviommu.h>

#include <linux/kvm_host.h>
#include <nvhe/pkvm.h>

static bool pkvm_guest_iommu_map(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	return false;
}

static bool pkvm_guest_iommu_unmap(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	return false;
}

static bool pkvm_guest_iommu_attach_dev(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	return false;
}

static bool pkvm_guest_iommu_detach_dev(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	return false;
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

static bool pkvm_guest_iommu_alloc_domain(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	return false;
}

static bool pkvm_guest_iommu_free_domain(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	return false;
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
		return pkvm_guest_iommu_map(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_UNMAP_FUNC_ID:
		return pkvm_guest_iommu_unmap(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_ATTACH_DEV_FUNC_ID:
		return pkvm_guest_iommu_attach_dev(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_DETACH_DEV_FUNC_ID:
		return pkvm_guest_iommu_detach_dev(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_VERSION_FUNC_ID:
		return pkvm_guest_iommu_version(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_GET_FEATURE_FUNC_ID:
		return pkvm_guest_iommu_get_feature(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_ALLOC_DOMAIN_FUNC_ID:
		return pkvm_guest_iommu_alloc_domain(hyp_vcpu);
	case ARM_SMCCC_VENDOR_HYP_KVM_IOMMU_FREE_DOMAIN_FUNC_ID:
		return pkvm_guest_iommu_free_domain(hyp_vcpu);
	}

	return false;
}

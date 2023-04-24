// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */
#include <nvhe/pviommu-host.h>

struct pviommu_host pviommus[MAX_NR_PVIOMMU];

int pkvm_pviommu_attach(struct kvm *host_kvm, int pviommu)
{
	return -ENODEV;
}

int pkvm_pviommu_add_vsid(struct kvm *host_kvm, int pviommu,
			  pkvm_handle_t iommu, u32 sid, u32 vsid)
{
	return -ENODEV;
}

int pkvm_pviommu_finalise(struct pkvm_hyp_vm *hyp_vm)
{
	return 0;
}

void pkvm_pviommu_teardown(struct pkvm_hyp_vm *hyp_vm)
{
}

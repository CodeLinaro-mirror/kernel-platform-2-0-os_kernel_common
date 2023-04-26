// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */
#ifndef __PVIOMMU_HOST_H
#define __PVIOMMU_HOST_H

#include <linux/kvm_host.h>
#include <nvhe/pkvm.h>

/* Ideally these are dynamically allocated. */
#define MAX_NR_PVIOMMU					32
#define MAX_NR_SID_PER_PVIOMMU				16

struct pviommu_route {
	pkvm_handle_t iommu;
	u32 sid;
};

int pkvm_pviommu_attach(struct kvm *host_kvm, int pviommu);
int pkvm_pviommu_add_vsid(struct kvm *host_kvm, int pviommu,
			  pkvm_handle_t iommu, u32 sid, u32 vsid);
int pkvm_pviommu_finalise(struct pkvm_hyp_vm *hyp_vm);
void pkvm_pviommu_teardown(struct pkvm_hyp_vm *hyp_vm);
int pkvm_pviommu_route(struct pkvm_hyp_vm *hyp_vm, pkvm_handle_t viommu, u32 vsid,
		       struct pviommu_route *route);

struct pviommu_entry {
	pkvm_handle_t iommu;
	u32 sid;
	u32 vsid;
};

struct pviommu_host {
	struct kvm *kvm;
	int pviommu_id;
	int nr_entries;
	struct pviommu_entry entries[MAX_NR_SID_PER_PVIOMMU];
	struct list_head list;
	bool finalized;
};

#endif /* __PVIOMMU_HOST_H */

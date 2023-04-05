/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */
#ifndef __ARM64_KVM_NVHE_PVIOMMU_H__
#define __ARM64_KVM_NVHE_PVIOMMU_H__

/* Implemented version of the API */
#define PVIOMMU_VERSION				0x1000
#define PVIOMMU_REQUEST_FEATURE_PGSZ_BITMAP	0x1

bool kvm_handle_pviommu_hvc(struct kvm_vcpu *vcpu, u64 *exit_code);

#endif /* __ARM64_KVM_NVHE_PVIOMMU_H__ */

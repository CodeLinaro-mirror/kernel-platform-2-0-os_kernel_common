# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_GUNYAH_PLATFORM_HOOKS) += gunyah_platform_hooks.o
obj-$(CONFIG_GUNYAH_QCOM_PLATFORM) += gunyah_qcom.o

gunyah-y += rsc_mgr.o rsc_mgr_rpc.o vm_mgr.o vm_mgr_mm.o
obj-$(CONFIG_GUNYAH) += gunyah.o

obj-$(CONFIG_GUNYAH_VCPU) += gunyah_vcpu.o
obj-$(CONFIG_GUNYAH_IRQFD) += gunyah_irqfd.o
obj-$(CONFIG_GUNYAH_IOEVENTFD) += gunyah_ioeventfd.o

obj-$(CONFIG_GH_DBL) += gh_dbl.o
obj-$(CONFIG_GH_MSGQ) += gh_msgq.o
obj-$(CONFIG_GH_RM_DRV) += gh_rm_drv.o
gh_rm_drv-y += gh_rm_core.o gh_rm_iface.o
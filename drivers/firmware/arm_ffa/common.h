/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 ARM Ltd.
 */

#ifndef _FFA_COMMON_H
#define _FFA_COMMON_H

#include <linux/arm-smccc.h>
#include <linux/err.h>

typedef void (*ffa_fn)(struct arm_smccc_1_2_regs, struct arm_smccc_1_2_regs *);

int arm_ffa_bus_init(void);
void arm_ffa_bus_exit(void);

static inline int __init ffa_transport_init(ffa_fn **invoke_ffa_fn)
{
	return -EOPNOTSUPP;
}

#endif /* _FFA_COMMON_H */

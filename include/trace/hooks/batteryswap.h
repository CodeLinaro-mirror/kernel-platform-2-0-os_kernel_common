/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM batteryswap

#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_BATTERYSWAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_BATTERYSWAP_H
#include <trace/hooks/vendor_hooks.h>

DECLARE_HOOK(android_vh_check_battery_swap,
	TP_PROTO(int *bs_flag),
	TP_ARGS(bs_flag));

#endif /* _TRACE_HOOK_BATTERYSWAP_H */
/* This part must be outside protection */
#include <trace/define_trace.h>

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Google, Inc.
 */

#include <linux/platform_device.h>
#include <linux/trusty/smcall.h>
#include <linux/trusty/trusty.h>

#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>

#include "trusty-smc.h"
#include "trusty-private.h"
#include "trusty-trace.h"

static u32 trusty_smc_send_direct_msg(struct device *dev, unsigned long fid,
				      unsigned long a0, unsigned long a1,
				      unsigned long a2)
{
	u32 ret;

	trace_trusty_smc(fid, a0, a1, a2);

	ret = trusty_smc8(fid, a0, a1, a2, 0, 0, 0, 0).r0;

	trace_trusty_smc_done(ret);

	return ret;
}

static int trusty_smc_share_memory(struct device *dev, u64 *id,
				   struct scatterlist *sglist,
				   unsigned int nents, pgprot_t pgprot, u64 tag)
{
	struct trusty_state *s = platform_get_drvdata(to_platform_device(dev));
	int ret;
	struct ns_mem_page_info pg_inf;
	struct scatterlist *sg;
	size_t count;

	if (WARN_ON(nents < 1))
		return -EINVAL;

	if (nents != 1) {
		dev_err(s->dev, "%s: old trusty version does not support non-contiguous memory objects\n",
				__func__);
		return -EOPNOTSUPP;
	}

	count = dma_map_sg(dev, sglist, nents, DMA_BIDIRECTIONAL);
	if (count != nents) {
		dev_err(s->dev, "failed to dma map sg_table\n");
		return -EINVAL;
	}

	sg = sglist;
	ret = trusty_encode_page_info(&pg_inf, phys_to_page(sg_dma_address(sg)),
				      pgprot);
	if (ret) {
		dev_err(s->dev, "%s: trusty_encode_page_info failed\n",
			__func__);
		dma_unmap_sg(dev, sglist, nents, DMA_BIDIRECTIONAL);
		return ret;
	}

	*id = pg_inf.compat_attr;
	return 0;
}

static int trusty_smc_lend_memory(struct device *dev, u64 *id,
				  struct scatterlist *sglist,
				  unsigned int nents, pgprot_t pgprot, u64 tag)
{
	return -EOPNOTSUPP;
}

static int trusty_smc_reclaim_memory(struct device *dev, u64 id,
				     struct scatterlist *sglist,
				     unsigned int nents)
{
	struct trusty_state *s = platform_get_drvdata(to_platform_device(dev));

	if (WARN_ON(nents < 1))
		return -EINVAL;

	if (WARN_ON(s->api_version >= TRUSTY_API_VERSION_MEM_OBJ))
		return -EINVAL;

	if (nents != 1) {
		dev_err(s->dev, "%s: not supported\n", __func__);
		return -EOPNOTSUPP;
	}

	dma_unmap_sg(dev, sglist, nents, DMA_BIDIRECTIONAL);

	return 0;
}

static const struct trusty_msg_ops trusty_smc_msg_ops = {
	.send_direct_msg = &trusty_smc_send_direct_msg,
};

static const struct trusty_mem_ops trusty_smc_mem_ops = {
	.trusty_share_memory = &trusty_smc_share_memory,
	.trusty_lend_memory = &trusty_smc_lend_memory,
	.trusty_reclaim_memory = &trusty_smc_reclaim_memory,
};

int trusty_smc_transport_setup(struct device *dev)
{
	int rc;
	struct trusty_state *s = platform_get_drvdata(to_platform_device(dev));

	rc = trusty_init_api_version(s, dev, &trusty_smc_send_direct_msg);
	if (rc != 0)
		return rc;

	/*
	 * Initialize Trusty msg calls with Trusty SMC ABI
	 */
	s->msg_ops = &trusty_smc_msg_ops;

	/*
	 * Initialize Trusty memory operations with Trusty SMC ABI only when
	 * Trusty API version is below TRUSTY_API_VERSION_MEM_OBJ.
	 */
	if (s->api_version < TRUSTY_API_VERSION_MEM_OBJ)
		s->mem_ops = &trusty_smc_mem_ops;

	return 0;
}

void trusty_smc_transport_cleanup(struct device *dev)
{
	struct trusty_state *s = platform_get_drvdata(to_platform_device(dev));

	if (s->msg_ops == &trusty_smc_msg_ops)
		s->msg_ops = NULL;

	if (s->mem_ops == &trusty_smc_mem_ops)
		s->mem_ops = NULL;
}

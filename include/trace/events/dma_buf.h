/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM dma_buf

#if !defined(_TRACE_DMA_BUF_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DMA_BUF_H

#include <linux/tracepoint.h>
#include <linux/fs.h>

DECLARE_EVENT_CLASS(dma_buf,

	TP_PROTO(struct dma_buf *dmabuf),

	TP_ARGS(dmabuf),

	TP_STRUCT__entry(
		__field(unsigned long, inode_num)
		__field(size_t, len)
		__string(exp_name, dmabuf->exp_name)
	),

	TP_fast_assign(
		__entry->inode_num = file_inode(dmabuf->file)->i_ino;
		__entry->len = dmabuf->size;
		__assign_str(exp_name, dmabuf->exp_name)
	),

	TP_printk("ino=%lu exp=%s len=%zu", __entry->inode_num,
		  __get_str(exp_name), __entry->len)
);

DEFINE_EVENT(dma_buf, dma_buf_export,

	TP_PROTO(struct dma_buf *dmabuf),

	TP_ARGS(dmabuf)
);

DEFINE_EVENT(dma_buf, dma_buf_release,

	TP_PROTO(struct dma_buf *dmabuf),

	TP_ARGS(dmabuf)
);

DECLARE_EVENT_CLASS(dma_buf_dev_usage,

	TP_PROTO(struct dma_buf_attachment *attach),

	TP_ARGS(attach),

	TP_STRUCT__entry(
		__field(unsigned long, inode_num)
		__field(size_t, len)
		__string(device_name, dev_name(attach->dev))
	),

	TP_fast_assign(
		__entry->inode_num = file_inode(attach->dmabuf->file)->i_ino;
		__entry->len = attach->dmabuf->size;
		__assign_str(device_name, dev_name(attach->dev));
	),

	TP_printk("ino=%lu len=%zu dev=%s", __entry->inode_num,
		  __entry->len, __get_str(device_name))
);

DEFINE_EVENT(dma_buf_dev_usage, dma_buf_map_attachment,

	TP_PROTO(struct dma_buf_attachment *attach),

	TP_ARGS(attach)
);

DEFINE_EVENT(dma_buf_dev_usage, dma_buf_unmap_attachment,

	TP_PROTO(struct dma_buf_attachment *attach),

	TP_ARGS(attach)
);


#endif /*  _TRACE_DMA_BUF_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

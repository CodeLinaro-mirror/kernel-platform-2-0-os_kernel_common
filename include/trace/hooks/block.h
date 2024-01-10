/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM block

#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_BLOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_BLOCK_H

#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

#if defined(__GENKSYMS__) || !defined(CONFIG_BLOCK)
struct blk_mq_tags;
struct blk_mq_alloc_data;
struct blk_mq_tag_set;
struct bio;
struct bio_vec;
struct page;
#else
/* struct blk_mq_tags */
#include <../block/blk-mq-tag.h>
/* struct blk_mq_alloc_data */
#include <../block/blk-mq.h>
/* struct blk_mq_tag_set */
#include <linux/blk-mq.h>
/* struct bio */
#include <linux/blk_types.h>
/* struct bio_vec */
#include <linux/bvec.h>
/* struct page */
#include <linux/mm_types.h>
#endif /* __GENKSYMS__ */

DECLARE_HOOK(android_vh_blk_alloc_rqs,
	TP_PROTO(size_t *rq_size, struct blk_mq_tag_set *set,
		struct blk_mq_tags *tags),
	TP_ARGS(rq_size, set, tags));

DECLARE_HOOK(android_vh_blk_rq_ctx_init,
	TP_PROTO(struct request *rq, struct blk_mq_tags *tags,
		struct blk_mq_alloc_data *data, u64 alloc_time_ns),
	TP_ARGS(rq, tags, data, alloc_time_ns));

DECLARE_RESTRICTED_HOOK(android_rvh_bio_free,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio), 1);

DECLARE_HOOK(android_vh_bio_uninit,
	TP_PROTO(bool *skip, struct bio *bio),
	TP_ARGS(skip, bio));

DECLARE_HOOK(android_vh_bio_clone_fast,
	TP_PROTO(struct bio *bio_src, struct bio *bio_dst),
	TP_ARGS(bio_src, bio_dst));

DECLARE_HOOK(android_vh_bio_try_merge_page,
	TP_PROTO(bool *skip, bool *status, struct bio *bio,
		 struct bio_vec *bv, struct page *page, unsigned int len,
		 unsigned int off, bool *same_page),
	TP_ARGS(skip, status, bio, bv, page, len, off, same_page));

DECLARE_RESTRICTED_HOOK(android_rvh_bio_endio,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio), 1);

#endif /* _TRACE_HOOK_BLOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

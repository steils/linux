#undef TRACE_SYSTEM
#define TRACE_SYSTEM cma

#if !defined(_TRACE_CMA_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CMA_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(cma_alloc,

	TP_PROTO(struct cma *cma, unsigned long pfn, int count),

	TP_ARGS(cma, pfn, count),

	TP_STRUCT__entry(
		__field(unsigned long, pfn)
		__field(unsigned long, count)
	),

	TP_fast_assign(
		__entry->pfn = pfn;
		__entry->count = count;
	),

	TP_printk("pfn=%lu page=%p count=%lu\n",
		  __entry->pfn,
		  pfn_to_page(__entry->pfn),
		  __entry->count)
);

TRACE_EVENT(cma_release,

	TP_PROTO(struct cma *cma, unsigned long pfn, int count),

	TP_ARGS(cma, pfn, count),

	TP_STRUCT__entry(
		__field(unsigned long, pfn)
		__field(unsigned long, count)
	),

	TP_fast_assign(
		__entry->pfn = pfn;
		__entry->count = count;
	),

	TP_printk("pfn=%lu page=%p count=%lu\n",
		  __entry->pfn,
		  pfn_to_page(__entry->pfn),
		  __entry->count)
);

#endif /* _TRACE_CMA_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

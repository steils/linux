#ifndef __MM_CMA_H__
#define __MM_CMA_H__

#include <linux/sched.h>

struct cma {
	unsigned long   base_pfn;
	unsigned long   count;
	unsigned long   *bitmap;
	unsigned int order_per_bit; /* Order of pages represented by one bit */
	struct mutex    lock;
#ifdef CONFIG_CMA_DEBUGFS
	struct hlist_head mem_head;
	spinlock_t mem_head_lock;
	struct list_head buffers_list;
	struct mutex	list_lock;
#endif
};

#ifdef CONFIG_CMA_DEBUGFS
struct cma_buffer {
	unsigned long pfn;
	unsigned long count;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	unsigned long trace_entries[16];
	unsigned int nr_entries;
	struct list_head list;
};
#endif

extern struct cma cma_areas[MAX_CMA_AREAS];
extern unsigned cma_area_count;

static unsigned long cma_bitmap_maxno(struct cma *cma)
{
	return cma->count >> cma->order_per_bit;
}

#endif

/*
 * 	bvl.c
 *
 * 2010 Copyright (c) Ricardo Chen <ricardo.chen@semptianc.om>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "bvl.h"

unsigned long 
	count_alloc[NR_CPUS], count_free[NR_CPUS], 
	count_hook[NR_CPUS], count_unhook[NR_CPUS],
	count_update[NR_CPUS], count_miss[NR_CPUS],
	count_cache[NR_CPUS], count_full[NR_CPUS],
	count_node[NR_CPUS], count_mem[NR_CPUS],
	count_page;

struct avl_allocator_data avl_allocator[NR_CPUS];

#define avl_ptr_to_chunk(ptr)	(struct avl_chunk *)(ptr + BVL_MEM_SIZE)

/*
 * Get node pointer from address.
 */
static inline struct avl_node *avl_get_node_ptr(unsigned long ptr)
{
	struct page *page = virt_to_page(ptr);
	struct avl_node *node = (struct avl_node *)(page->lru.next);

	return node;
}

/*
 * Set node pointer for page for given address.
 */
static void avl_set_node_ptr(unsigned long ptr, struct avl_node *node, int order)
{
	int nr_pages = 1<<order, i;
	struct page *page = virt_to_page(ptr);

	for (i=0; i<nr_pages; ++i) {
		//printk("page->lru.next %p node %p ptr %p\n", page->lru.next, node, ptr);
		page->lru.next = (void *)node;
		page++;
	}
}

/*
 * Get allocation CPU from address.
 */
static inline int avl_get_cpu_ptr(unsigned long ptr)
{
	struct page *page = virt_to_page(ptr);
	int cpu = (int)(unsigned long)(page->lru.prev);

	return cpu;
}

/*
 * Set allocation cpu for page for given address.
 */
static void avl_set_cpu_ptr(unsigned long ptr, int cpu, int order)
{
	int nr_pages = 1<<order, i;
	struct page *page = virt_to_page(ptr);

	for (i=0; i<nr_pages; ++i) {
		page->lru.prev = (void *)(unsigned long)cpu;
		page++;
	}
}

/*
 * Convert pointer to node's value.
 * Node's value is a start address for contiguous chunk bound to given node.
 */
static inline unsigned long avl_ptr_to_value(void *ptr)
{
	struct avl_node *node = avl_get_node_ptr((unsigned long)ptr);
	return node->value;
}

/*
 * Convert pointer into offset from start address of the contiguous chunk
 * allocated for appropriate node.
 */
static inline int avl_ptr_to_offset(void *ptr)
{
	return ((unsigned long)ptr - avl_ptr_to_value(ptr))/BVL_CELL_SIZE;
}


/*
 * Fill zc_data structure for given pointer and node.
 */
static void __avl_fill_zc(struct zc_data *zc, void *ptr, struct avl_node *node, int r_size)
{
	u32 off;

	//off = ((unsigned long)node & ~PAGE_MASK)/sizeof(struct avl_node)*((1U<<node->entry->avl_node_order)<<PAGE_SHIFT);
	off = ((unsigned long)node - (unsigned long)(node->entry->avl_node_array[0]))/sizeof(struct avl_node)*((1U<<node->entry->avl_node_order)<<PAGE_SHIFT);
	zc->off = off+avl_ptr_to_offset(ptr)*BVL_CELL_SIZE;
	//printk("off %d avl_ptr_to_offset(ptr) %d ptr %p node %p sizeof(struct avl_node) %d node->entry->avl_node_order %d value %p\n", 
	//	   off, avl_ptr_to_offset(ptr), ptr, node, sizeof(struct avl_node), node->entry->avl_node_order, node->value);

	zc->data.ptr = ptr;
	//zc->s_size = size;
	zc->r_size = r_size;
	zc->entry = node->entry->avl_entry_num;
	zc->cpu = avl_get_cpu_ptr((unsigned long)ptr);

	//printk("%s: ptr: %p, size: %u, off: %u, cpu %d, entry %d\n",
	//		__func__, ptr, size, zc->off,  zc->cpu, zc->entry);

}

void avl_fill_zc(struct zc_data *zc, void *ptr, int r_size)
{
	struct avl_node *node = avl_get_node_ptr((unsigned long)ptr);

	__avl_fill_zc(zc, ptr, node, r_size);

	
	//printk("%s: ptr: %p, size: %u, off: %u, node: entry: %u, order: %u, number: %u.\n",
	//		__func__, ptr, size, zc->off, node->entry->avl_entry_num,
	//		node->entry->avl_node_order, node->entry->avl_node_num);

}

static inline int avl_zc_ring_unused(struct zc_control *zc)
{
	if (zc->zc_used > zc->zc_pos)
		return zc->zc_used - zc->zc_pos - 1;

	return zc->zc_num + zc->zc_used - zc->zc_pos - 1;
}

/*
 * Update zero-copy information in given @node.
 * @node - node where given pointer @ptr lives
 * @num - number of @BVL_MIN_SIZE chunks given pointer @ptr embeds
 */
static void avl_update_zc(struct avl_node *node, void *ptr, int r_size, int i)
{
	struct zc_control *ctl = &zc_sniffer[i];
	unsigned long flags;
	int pos;

	spin_lock_irqsave(&ctl->zc_lock, flags);
	if(avl_zc_ring_unused(ctl)) {
		pos = ctl->zc_pos;
	}else{
		count_miss[i]++;
		spin_unlock_irqrestore(&ctl->zc_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&ctl->zc_lock, flags);

	do {
		struct zc_data *zc = &ctl->zcb[pos];
		struct avl_chunk *ch = avl_ptr_to_chunk(ptr);;

		//printk("fill at pos %d\n", pos);

		atomic_inc(&ch->refcnt);
		count_update[i]++;
		__avl_fill_zc(zc, ptr, node, r_size);

		pos++;
		if(pos == ctl->zc_num) {
			pos = 0;
		}
		wake_up(&ctl->zc_wait);

		ulog("%s: used: %u, pos: %u, num: %u, ptr: %p, size: %u, off: %u.\n",
				__func__, ctl->zc_used, ctl->zc_pos, ctl->zc_num, ptr, zc->size, zc->off);
	}while(0);

	spin_lock_irqsave(&ctl->zc_lock, flags);
	ctl->zc_pos = pos;
	ctl->zc_max = 1;

	spin_unlock_irqrestore(&ctl->zc_lock, flags);
}


/*
 * Free memory region of given size.
 */
static void __avl_free(void *ptr)
{
	int cpu = avl_get_cpu_ptr((unsigned long)ptr);
	struct avl_chunk *ch = avl_ptr_to_chunk(ptr);
	struct avl_free_list *l, *this = ptr;
	struct avl_allocator_data *alloc = &avl_allocator[cpu];

	spin_lock(&alloc->avl_free_lock);
	l = alloc->avl_free_list_head;
	alloc->avl_free_list_head = this;
	this->next = l;
	ch->canary = BVL_UNUSE_MAGIC;
	count_free[cpu]++;
	spin_unlock(&alloc->avl_free_lock);
	return;
}

/*
 * Free memory region of given size without sniffer data update.
 */
void avl_free_no_zc(void *ptr)
{
	unsigned long flags;
	//struct avl_free_list *l;
	//struct avl_allocator_data *alloc;
	struct avl_chunk *ch = avl_ptr_to_chunk(ptr);

	if (unlikely((ch->canary != BVL_CANARY))) {
		printk("Freeing destroyed object: ptr: %p, ch %p, canary: %x, must be %x, refcnt: %d, saved size: %u.\n",
				ptr, ch, ch->canary, BVL_CANARY, atomic_read(&ch->refcnt), ch->size);
        //WARN_ON("avl_free_no_zc");
        return;
	}

	if (atomic_dec_and_test(&ch->refcnt)) {
		local_irq_save(flags);
		__avl_free(ptr);
		local_irq_restore(flags);
	}
}

/*
 * Free memory region of given size.
 */
void avl_free(void *ptr, int sniff, int r_size)
{
	struct avl_chunk *ch = avl_ptr_to_chunk(ptr);
	int i;

	if (unlikely((ch->canary != BVL_CANARY))) {
		printk("Freeing destroyed object: ptr: %p, ch: %p, canary: %x, must be %x, refcnt: %d, saved size: %u.\n",
				ptr, ch, ch->canary, BVL_CANARY, atomic_read(&ch->refcnt), ch->size);
        //WARN_ON("avl_free");
        return;
	}

	for(i=0; i< ZC_MAX_SNIFFERS; i++){
		if(sniff & (1<<i)) {
			avl_update_zc(avl_get_node_ptr((unsigned long)ptr), ptr, r_size, i);
		}
	}
	
	avl_free_no_zc(ptr);
}

/*
 * Allocate memory region with given size and mode.
 * If allocation fails due to unsupported order, otherwise
 * allocate new node entry with given mode and try to allocate again
 * Cache growing happens only with 0-order allocations.
 */
static void avl_scan(int cpu)
{
	unsigned int i, j, osize = BVL_MEM_SIZE, size = BVL_CELL_SIZE;
	//void *ptr = NULL;
	//unsigned long flags;
	struct avl_allocator_data *alloc;
	struct avl_free_list 	*l=NULL;
	struct avl_node_entry *e;
	int num;
	int idx, off;
	alloc = &avl_allocator[cpu];

	//spin_lock_irqsave(&alloc->avl_node_lock, flags);
	list_for_each_entry(e, &alloc->avl_node_list, node_entry) {
		if(e->avl_entry_num == BVL_MAX_NODE_ENTRY_NUM) {
			printk("node for sniffer ring on CPU %d, not scanning...\n", cpu);
			BUG_ON( (cpu!=0) );
			alloc->zc_ring_zone = (void*)e->avl_node_array[0][0].value;
			continue;
		}
		num = e->avl_node_num; //*(1<<e->avl_node_order);

		idx = 0;
		off = 0;
		for (i=0; i<num; i++) {
			struct avl_node *node = &e->avl_node_array[idx][off];
			//printk("e %p ->avl_node_array[%d][%d] = %p\n", e, idx, off, node);

			if (++off >= BVL_NODES_ON_PAGE) {
				idx++;
				off = 0;
			}
			//printk("scan node %d @ %lx for entry %d:\n", i, node->value, e->avl_entry_num);
			for (j=0; j<((1<<e->avl_node_order)*(PAGE_SIZE/size)); j++) {
				struct avl_chunk *ch;
				unsigned long virt = node->value + (j*size);
				struct avl_free_list *this = (struct avl_free_list *) virt;
				//printk("[%lx ", virt);
				this->cpu = cpu;
				this->size = osize;
				l = alloc->avl_free_list_head;
				alloc->avl_free_list_head = this;
				this->next = l;
				ch = avl_ptr_to_chunk((void*)this);
				//printk("%p] ", ch);
				atomic_set(&ch->refcnt, 0);
				ch->canary = BVL_UNUSE_MAGIC;
				ch->size = osize;
				count_mem[cpu]++;
			}
			//printk("\n");
		}
	}
	//spin_unlock_irqrestore(&alloc->avl_node_lock, flags);
}

void *avl_alloc(unsigned int size, int cpu, gfp_t gfp_mask)
{
	unsigned int osize = size;
	//void *ptr = NULL;
	unsigned long flags;
	struct avl_allocator_data *alloc;
	struct avl_free_list 	*l=NULL;

	alloc = &avl_allocator[cpu];

	if(size > BVL_MEM_SIZE) {
		printk("fail to alloc size %d on CPU %d\n", size, cpu);
		WARN_ON("test");
		return NULL;
	}else
		size = BVL_MEM_SIZE;

	local_irq_save(flags);
	spin_lock(&alloc->avl_free_lock);

	if (alloc->avl_free_list_head) {
		l = alloc->avl_free_list_head;
		alloc->avl_free_list_head = l->next;
	}else{
		l = NULL;
		count_full[cpu]++;
	}
	spin_unlock(&alloc->avl_free_lock);

	local_irq_restore(flags);

	if(l) {
		struct avl_chunk *ch;
		ch = avl_ptr_to_chunk((void *)l);
		atomic_set(&ch->refcnt, 1);
		ch->canary = BVL_CANARY;
		ch->size = osize;
		//printk("unhook: ptr: %p, size: %u, ch %p, canary: %x, refcnt: %d, saved size: %u.\n",
		//	   l, osize, ch, ch->canary, ch->refcnt, ch->size);
		count_alloc[cpu]++;
	}

	return l;
}

/*
 * Add new node entry int network allocator.
 * must be called with disabled preemtpion.
 */
static void avl_node_entry_commit(struct avl_node_entry *entry, int cpu)
{
	int i, idx, off;

	idx = off = 0;
	for (i=0; i<entry->avl_node_num; ++i) {
		struct avl_node *node;

		node = &entry->avl_node_array[idx][off];
		//printk("entry %p node %p idx %d off %d\n", entry, node, idx, off);
		if (++off >= BVL_NODES_ON_PAGE) {
			idx++;
			off = 0;
		}
#if 1
		node->entry = entry;
#endif
		avl_set_cpu_ptr(node->value, cpu, entry->avl_node_order);
		avl_set_node_ptr(node->value, node, entry->avl_node_order);
		count_node[cpu]++;
	}

	spin_lock(&avl_allocator[cpu].avl_node_lock);
	entry->avl_entry_num = avl_allocator[cpu].avl_node_entry_num;
	list_add_tail(&entry->node_entry, &avl_allocator[cpu].avl_node_list);
	avl_allocator[cpu].avl_node_entry_num++;
	spin_unlock(&avl_allocator[cpu].avl_node_lock);

	printk("Network allocator cache has grown: entry: %u, number: %u, order: %u.\n",
			entry->avl_entry_num, entry->avl_node_num, entry->avl_node_order);
}

/*
 * Simple cache growing function - allocate as much as possible,
 * but no more than @BVL_NODE_NUM pages when there is a need for that.
 */
static struct avl_node_entry *avl_node_entry_alloc(gfp_t gfp_mask, int order)
{
	struct avl_node_entry *entry;
	int i, num = 0, idx, off, j;
	unsigned long ptr;
	unsigned long tmp;
	int otmp;

	entry = kzalloc(sizeof(struct avl_node_entry), gfp_mask);
	if (!entry)
		return NULL;

	entry->avl_node_array = kzalloc(BVL_NODE_PAGES * sizeof(void *), gfp_mask);
	if (!entry->avl_node_array)
		goto err_out_free_entry;

	otmp = get_order(BVL_NODE_PAGES*PAGE_SIZE);
	tmp = __get_free_pages(gfp_mask, otmp);
	//printk("allocated tmp %lu otmp %d %d\n", tmp, otmp, BVL_NODE_PAGES);
#if 0
	for (j=0; j<(1<<otmp); ++j)
		get_page(virt_to_page( tmp + (j<<PAGE_SHIFT)));
#endif

	for (i=0; i<BVL_NODE_PAGES; ++i) {
#if 0
		entry->avl_node_array[i] = (struct avl_node *)__get_free_page(gfp_mask);
		printk("entry->avl_node_array[i] = %p\n", entry->avl_node_array[i]);
		if (!entry->avl_node_array[i]) {
			num = i;
			goto err_out_free;
		}
#endif
		entry->avl_node_array[i] = (struct avl_node*)(tmp + (i<<PAGE_SHIFT));
		//printk("entry->avl_node_array[%d] = %p\n", i, entry->avl_node_array[i]);
		if (!entry->avl_node_array[i]) {
			num = i;
			goto err_out_free;
		}
	}

	idx = off = 0;

	ptr = __get_free_pages(gfp_mask | __GFP_ZERO, get_order(BVL_NODE_NUM*((1UL<<order)<<PAGE_SHIFT)));
	if(!ptr) {
		printk("Out of memory!!!!\n");
		goto err_out_free;
	}
	for (i=0; i<BVL_NODE_NUM; ++i) {
		struct avl_node *node;

#if 0
		ptr = __get_free_pages(gfp_mask | __GFP_ZERO, order);
		if (!ptr)
			break;
#endif

		node = &entry->avl_node_array[idx][off];

		if (++off >= BVL_NODES_ON_PAGE) {
			idx++;
			off = 0;
		}

		for (j=0; j<(1<<order); ++j){
			count_page++;
			entry->avl_node_pages++;
			get_page(virt_to_page(ptr + (j<<PAGE_SHIFT)));
		}

		node->value = ptr;

		ptr += ((1UL<<order)<<PAGE_SHIFT);
	}

	ulog("%s: entry: %p, node: %u, node_pages: %lu, node_num: %lu, order: %d, allocated: %d, container: %u, max_size: %u, min_size: %u, bits: %u.\n",
		__func__, entry, sizeof(struct avl_node), BVL_NODE_PAGES, BVL_NODE_NUM, order,
		i, BVL_CONTAINER_ARRAY_SIZE, BVL_MAX_SIZE, BVL_MIN_SIZE, ((1<<order)<<PAGE_SHIFT)/BVL_MIN_SIZE);

	if (i == 0)
		goto err_out_free;

	entry->avl_node_num = i;
	entry->avl_node_order = order;

	return entry;

err_out_free:
	for (i=0; i<BVL_NODE_PAGES; ++i)
		free_page((unsigned long)entry->avl_node_array[i]);
err_out_free_entry:
	kfree(entry);
	return NULL;
}


/*
 * Initialize per-cpu allocator data.
 */
static int avl_init_cpu(int cpu)
{
	unsigned int i, num;
	struct avl_allocator_data *alloc = &avl_allocator[cpu];
	struct avl_node_entry *entry;

	spin_lock_init(&alloc->avl_free_lock);
	spin_lock_init(&alloc->avl_node_lock);
	INIT_LIST_HEAD(&alloc->avl_node_list);

	if(cpu == 0) {
		num = BVL_MAX_NODE_ENTRY_NUM+1;
	}else
		num = BVL_MAX_NODE_ENTRY_NUM;
	for (i=0; i<num; i++)
	{
		entry = avl_node_entry_alloc(GFP_KERNEL, BVL_ORDER);
		if (!entry)
			goto err_out_exit;

		avl_node_entry_commit(entry, cpu);
	}

	avl_scan(cpu);

	return 0;

err_out_exit:
	return -ENOMEM;
}

/*
 * Initialize network allocator.
 */
int avl_init(void)
{
	int err, cpu;

	for(cpu=0; cpu<NTA_NR_CPUS; cpu++) {
		err = avl_init_cpu(cpu);
		if (err)
			goto err_out;
	}

	err = avl_init_zc();

	printk(KERN_INFO "Network tree allocator has been initialized.\n");
	return 0;

err_out:
	panic("Failed to initialize network allocator.\n");

	return -ENOMEM;
}


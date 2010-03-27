/*
 * 	zc.c
 *
 * 2010 Copyright (c) Ricardo Chen <ricardo.chen@semptianc.om>
 * All rights reserved.
 * 
 * 2006 Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/ioctl.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>

#include "bvl.h"
#include "nta.h"

struct zc_private
{
	struct zc_data	*zcb;
	struct mutex	lock;
	int		cpu;
	int		sniff_id;
};

struct zc_control zc_sniffer[ZC_MAX_SNIFFERS];
int zc_users;

static int zc_release(struct inode *inode, struct file *file)
{
	struct zc_private *priv = file->private_data;

	kfree(priv);
	return 0;
}

static int zc_open(struct inode *inode, struct file *file)
{
	struct zc_private *priv;
	struct zc_control *ctl = &zc_sniffer[0];

	priv = kzalloc(sizeof(struct zc_private) + ctl->zc_num * sizeof(struct zc_data), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->zcb = (struct zc_data *)(priv+1);
	priv->cpu = 0; /* Use CPU0 by default */
	priv->sniff_id = 0; /* Default sniffer id */
	mutex_init(&priv->lock);

	file->private_data = priv;

	return 0;
}

static int zc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct zc_private *priv = file->private_data;
	struct avl_allocator_data *alloc = &avl_allocator[priv->cpu];
	struct avl_node_entry *e;
	unsigned long start = vma->vm_start;
	int err = 0, idx, off;
	unsigned int i, j, st, num=0, total_num=0, page_count=0;

	st = vma->vm_pgoff;
	total_num = (vma->vm_end - vma->vm_start)/PAGE_SIZE;

	//printk("%s: start: %lx, end: %lx, total_num: %u, st: %u.\n", __func__, start, vma->vm_end, total_num, st);

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_flags |= VM_RESERVED;
	vma->vm_file = file;

	//spin_lock_irqsave(&alloc->avl_node_lock, flags);
	list_for_each_entry(e, &alloc->avl_node_list, node_entry) {
		if (st != e->avl_entry_num) {
#if 0
			printk("%s: continue on cpu: %d, e: %p %d, total_num: %u, node_num: %u, node_order: %u, pages_in_node: %u, st: %u.\n",
					__func__, priv->cpu, e, e->avl_entry_num, total_num, e->avl_node_num, e->avl_node_order,
					e->avl_node_num*(1U<<e->avl_node_order), st);
#endif
			continue;
		}
		num = min_t(unsigned int, total_num, e->avl_node_num*(1<<e->avl_node_order));

		//printk("%s: cpu: %d, e: %p, total_num: %u, node_num: %u, node_order: %u, st: %u, num: %u.\n",
		//		__func__, priv->cpu, e, total_num, e->avl_node_num, e->avl_node_order, st, num);

		idx = 0;
		off = 0;
		//printk("[");
		for (i=0; i<num; ) {
			struct avl_node *node = &e->avl_node_array[idx][off];
			//printk("e %p ->avl_node_array[%d][%d] = %p\n", e, idx, off, node);

			if (++off >= BVL_NODES_ON_PAGE) {
				idx++;
				off = 0;
			}

			for (j=0; (j<(1<<e->avl_node_order)) && (i<num); ++j, ++i) {
				unsigned long virt = node->value + (j<<PAGE_SHIFT);
				page_count++;
				err = vm_insert_page(vma, start, virt_to_page(virt));
				if (err) {
					printk("\n%s: Failed to insert page for addr %lx into %lx, err: %d.\n",
							__func__, virt, start, err);
					break;
				}
				//printk("%lx ", virt);
				sta
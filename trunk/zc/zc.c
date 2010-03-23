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

#include "bvl.h"
#include "nta.h"

struct zc_private
{
	struct zc_data	*zcb;
	struct mutex	lock;
	int		cpu;
};

static char zc_name[] = "zc";
static int zc_major;
struct zc_control zc_sniffer;

static int zc_release(struct inode *inode, struct file *file)
{
	struct zc_private *priv = file->private_data;

	kfree(priv);
	return 0;
}

static int zc_open(struct inode *inode, struct file *file)
{
	struct zc_private *priv;
	struct zc_control *ctl = &zc_sniffer;

	priv = kzalloc(sizeof(struct zc_private) + ctl->zc_num * sizeof(struct zc_data), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->zcb = (struct zc_data *)(priv+1);
	priv->cpu = 0; /* Use CPU0 by default */
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
				start += PAGE_SIZE;
			}
			//printk("\n");
		}
		//printk("]\n")
		if (err)
			break;
		//printk("total_num %d num %d page_count %d\n", total_num, num, page_count);
		total_num -= num;

		if (total_num == 0)
			break;
	}
	//spin_unlock_irqrestore(&alloc->avl_node_lock, flags);
	if(!num) {
		return -ENXIO;
	}
	return err;
}

static ssize_t zc_write(struct file *file, const char __user *buf, size_t size, loff_t *off)
{
	ssize_t sz = 0;
	struct zc_private *priv = file->private_data;
	unsigned long flags;
	unsigned int req_num = size/sizeof(struct zc_data), cnum, csize, i;
	struct zc_control *ctl = &zc_sniffer;

	while (size) {
		cnum = min_t(unsigned int, req_num, ctl->zc_num);
		csize = cnum*sizeof(struct zc_data);

		if (copy_from_user(priv->zcb, buf, csize)) {
			printk("%s: copy_from_user() failed.\n", __func__);
			break;
		}

		spin_lock_irqsave(&ctl->zc_lock, flags);
		for (i=0; i<cnum; ++i){
			avl_free_no_zc(priv->zcb[i].data.ptr, priv->zcb[i].s_size);
		}
		//ctl->zc_used -= cnum;
		spin_unlock_irqrestore(&ctl->zc_lock, flags);

		sz += csize;
		size -= csize;
		buf += csize;
	}

	return sz;
}

static ssize_t zc_read(struct file *file, char __user *buf, size_t size, loff_t *off)
{
	ssize_t sz = 0;
	struct zc_private *priv = file->private_data;
	unsigned long flags;
	unsigned int req_num = size/sizeof(struct zc_data), cnum, csize;
	struct zc_control *ctl = &zc_sniffer;

	if(req_num != DEFAULT_ZC_NUM) {
		return -EINVAL;
	}
	wait_event_interruptible(ctl->zc_wait, ctl->zc_used > 0);

	spin_lock_irqsave(&ctl->zc_lock, flags);
	cnum = min_t(unsigned int, req_num, ctl->zc_used);
	csize = cnum*sizeof(struct zc_data);
	if (ctl->zc_used) {
#if 0
		if (ctl->zc_pos >= ctl->zc_used) {
			pos = ctl->zc_pos - ctl->zc_used;
			memcpy(priv->zcb, &ctl->zcb[pos], csize);
			ctl->zc_used -= cnum;
			ctl->zc_pos
		} else {
			len = ctl->zc_used - ctl->zc_pos;
			pos = ctl->zc_num - len;
			memcpy(priv->zcb, &ctl->zcb[pos],
					len*sizeof(struct zc_data));
			memcpy(&priv->zcb[len], &ctl->zcb[0], ctl->zc_pos*sizeof(struct zc_data));

		}
#endif
		memcpy(priv->zcb, ctl->zcb, csize);
		ctl->zc_pos = 0;
		ctl->zc_used = 0;
	}
	spin_unlock_irqrestore(&ctl->zc_lock, flags);

	sz = cnum;

	if (copy_to_user(buf, priv->zcb, csize))
		sz = -EFAULT;

	return sz;
}

static unsigned int zc_poll(struct file *file, struct poll_table_struct *wait)
{
	struct zc_control *ctl = &zc_sniffer;
	unsigned int poll_flags = 0;

	poll_wait(file, &ctl->zc_wait, wait);
	
	if (ctl->zc_used)
		poll_flags = POLLIN | POLLRDNORM;

	return poll_flags;
}

static int zc_ctl_alloc(struct zc_alloc_ctl *ctl, void __user *arg)
{
	void *ptr;
	unsigned int size;
	
	ctl->zc.s_size = MBUF_DATA_ALIGN(BVL_MBUF_LEN);

	size = MBUF_DATA_ALIGN(ctl->zc.s_size) + sizeof(struct mbuf_shared_info);

	if(size > BVL_MEM_SIZE) {
		return -ENOMEM;
	}

	ptr = avl_alloc(size, ctl->zc.cpu, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	//printk("alloc ptr %p on cpu %d\n", ptr, ctl->zc.cpu);
	avl_fill_zc(&ctl->zc, ptr, ctl->zc.s_size, ctl->zc.r_size);

	memset(ptr, 0, size);

	if (copy_to_user(arg, ctl, sizeof(struct zc_alloc_ctl))) {
		printk("!!! fail to copy to user!\n");
		avl_free(ptr, 0, size, ctl->zc.r_size);
		return -EFAULT;
	}

	return 0;
}

static inline struct avl_node *avl_get_node_ptr(unsigned long ptr)
{
	struct page *page = virt_to_page(ptr);
	struct avl_node *node = (struct avl_node *)(page->lru.next);

	return node;
}

static unsigned long count_commit;

static int zc_ctl_commit(struct zc_alloc_ctl *ctl)
{
	char *data;
	struct m_buf *mbuf;
	unsigned int data_len;
	struct mbuf_shared_info *shinfo;
	struct net_device *dev=NULL;
	int		(*hard_start_xmit) (struct m_buf *mbuf,
							struct net_device *dev);

	//printk("%s: ptr: %p, size: %u, reserved: %u, type: %x.\n",
	//		__func__, ctl->zc.data.ptr, ctl->zc.size, ctl->res_len, ctl->type);

	/* It must be calculated using provided offset
	 * and not blindly used by kernel. The same applies
	 * to sniffer freeing process.
	 */
	data = ctl->zc.data.ptr;
	data_len = ctl->zc.r_size;

	dev = zc_sniffer.netdev[ctl->zc.netdev_index];
	if(dev)
		hard_start_xmit = zc_sniffer.hard_start_xmit;
	else
		hard_start_xmit = NULL;
#if 0
	if(!*data){
		struct avl_node *node = avl_get_node_ptr((unsigned long)data);
		printk("!!!ptr: %p, cpu: %u, off: %u, node: entry: %u, order: %u, number: %u.\n",
				data, ctl->zc.cpu, ctl->zc.off, node->entry->avl_entry_num,
				node->entry->avl_node_order, node->entry->avl_node_num);
	}
#endif

	mbuf = nta_alloc_mbuf_empty(ctl->zc.s_size, GFP_KERNEL);
	if (!mbuf){
		printk("no mbuf could be allocated %lu\n", count_commit);
		return -ENOMEM;
	}

	count_commit++;

	mbuf->head = data;
	mbuf->data = data;
	mbuf->tail = data;
	mbuf->end  = data + SKB_DATA_ALIGN(ctl->zc.s_size);
	//printk("mbuf head %p end %p len %d size %d %d\n",
	//	   mbuf->head, mbuf->end, mbuf->end-mbuf->head, ctl->zc.size,
	//	   SKB_DATA_ALIGN(ctl->zc.size));

	mbuf->protocol = htons(ctl->proto);

	shinfo = mbuf_shinfo(mbuf);
	atomic_set(&shinfo->dataref, 1);
	shinfo->nr_frags  = 0;
	shinfo->gso_size = 0;
	shinfo->gso_segs = 0;
	shinfo->gso_type = 0;
	shinfo->ip6_frag_id = 0;
	shinfo->frag_list = NULL;

	mbuf->csum = 0;

	mbuf->dir = NTA_DIR_TX;
	//printk("!!! mbuf->len = %d\n", mbuf->len);
	mbuf_reserve(mbuf, ctl->res_len);
	mbuf_put(mbuf, data_len-ctl->res_len);

	if(0){
		int x;
		printk("zc commit: len %d, data %p\n", mbuf->len, mbuf->data);
		for(x=0; x<32; x++) {
			printk("%02x ", mbuf->data[x]);
			if(!((x+1)%8)) {
				printk("\n");
			}
		}

	}

	//printk("%lu: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, proto: %u, len: %u, mbuf_len: %u.\n",
	//		count_commit, NIPQUAD(iph->saddr), ntohs(thdr[0]),
	//		NIPQUAD(iph->daddr), ntohs(thdr[1]),
	//		iph->protocol, data_len, mbuf->len);

	//mbuf->h.th = (void *)thdr;
	//mbuf->nh.iph = iph;
#if 0 
	printk("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, proto: %u, dev: %s, mbuf: %p, data: %p data_len %d ctl->res_len %d.\n",
			NIPQUAD(iph->saddr), ntohs(thdr[0]),
			NIPQUAD(iph->daddr), ntohs(thdr[1]),
			iph->protocol, dev ? dev->name : "<NULL>",
			mbuf, mbuf->data, data_len, ctl->res_len);
#endif
	if(!dev) {
		nta_kfree_mbuf(mbuf);
	}else{
		if((*hard_start_xmit)(mbuf, dev)){
			mbuf->dir = 0;
			nta_kfree_mbuf(mbuf);
		}
	}

	return 0;

}

struct zc_status *zc_get_status(int cpu, unsigned int start)
{
	//unsigned long flags;
	struct avl_node_entry *e;
	struct avl_allocator_data *alloc = &avl_allocator[cpu];
	struct zc_status *st;
	struct zc_entry_status *es;
	unsigned int num = 0;

	st = kmalloc(sizeof(struct zc_status), GFP_KERNEL);
	if (!st)
		return NULL;

	//spin_lock_irqsave(&alloc->avl_node_lock, flags);
	list_for_each_entry(e, &alloc->avl_node_list, node_entry) {
		if (e->avl_entry_num >= start && num < ZC_MAX_ENTRY_NUM) {
			es = &st->entry[num];

			es->node_order = e->avl_node_order;
			es->node_num = e->avl_node_num;
			num++;
		}
	}
	//spin_unlock_irqrestore(&alloc->avl_node_lock, flags);

	st->entry_num = num;

	return st;
}

static int zc_get_netdev(char *dev_name)
{

	int i;
	struct zc_control *zc = &zc_sniffer;

	for(i=0; i<ZC_MAX_NETDEVS; i++) {
		if(zc->netdev[i]) {
			printk("%s %s\n", zc->netdev[i]->name, dev_name);
			if(!strcmp(zc->netdev[i]->name, dev_name)){
				return i;
			}
		}
	}

	return -1;
}

static int zc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct zc_alloc_ctl ctl;
	struct zc_private *priv = file->private_data;
	int cpu, ret = -EINVAL;
	unsigned int start;
	struct zc_status *st;
	unsigned long flags;

	mutex_lock(&priv->lock);

	switch (cmd) {
		case ZC_ALLOC:
		case ZC_COMMIT:
			if (copy_from_user(&ctl, (void __user *)arg, sizeof(struct zc_alloc_ctl))) {
				ret = -EFAULT;
				break;
			}

			if (cmd == ZC_ALLOC)
				ret = zc_ctl_alloc(&ctl, (void __user *)arg);
			else
				ret = zc_ctl_commit(&ctl);
			break;
		case ZC_SET_CPU:
			if (copy_from_user(&cpu, (void __user *)arg, sizeof(int))) {
				ret = -EFAULT;
				break;
			}
			if (cpu < NR_CPUS && cpu >= 0) {
				priv->cpu = cpu;
				ret = 0;
			}
			break;
		case ZC_SET_SNIFF:
			{
				struct zc_sniff sniff;
				struct zc_control *zc = &zc_sniffer;
				int i;
				if (copy_from_user(&sniff, (void __user *)arg, sizeof(sniff))) {
					ret = -EFAULT;
					break;
				}
				i = sniff.dev_index;
				if(i<0 || i> ZC_MAX_NETDEVS 
					|| sniff.sniff_mode > ZC_SNIFF_ALL
				    || sniff.sniff_mode < 0
				    || !zc->netdev[i]){
					ret = -EINVAL;
					break;
				}
				spin_lock_irqsave(&zc_sniffer.zc_lock, flags);
				zc->sniff_mode[i] = sniff.sniff_mode;
				spin_unlock_irqrestore(&zc_sniffer.zc_lock, flags);
				ret = 0;
				break;
			}

		case ZC_GET_NETDEV:
			{
				struct zc_netdev zn;
				if (copy_from_user(&zn, (void __user *)arg, sizeof(zn))) {
					printk("%s: failed to read initial zc netdevice.\n", __func__);
					ret = -EFAULT;
					break;
				}
				printk("get device name %p\n", zn.dev_name);
				zn.index = zc_get_netdev(zn.dev_name);
				printk("get device index %d\n", zn.index);

				if (zn.index < 0) {
					ret = -EINVAL;
					break;
				}
	
				ret = 0;
				if (copy_to_user((void __user *)arg, &zn, sizeof(zn))) {
					printk("%s: failed to write to userspace.\n", __func__);
					ret = -EFAULT;
				}
				break;
			}
		case ZC_STATUS:
			if (copy_from_user(&start, (void __user *)arg, sizeof(unsigned int))) {
				printk("%s: failed to read initial entry number.\n", __func__);
				ret = -EFAULT;
				break;
			}

			st = zc_get_status(priv->cpu, start);
			if (!st) {
				ret = -ENOMEM;
				break;
			}

			ret = 0;
			if (copy_to_user((void __user *)arg, st, sizeof(struct zc_status))) {
				printk("%s: failed to write CPU%d status.\n", __func__, priv->cpu);
				ret = -EFAULT;
			}
			kfree(st);
			break;

	}

	mutex_unlock(&priv->lock);

	return ret;
}

static struct file_operations zc_ops = {
	.poll		= &zc_poll,
	.ioctl		= &zc_ioctl,
	.open 		= &zc_open,
	.release 	= &zc_release,
	.read		= &zc_read,
	.write		= &zc_write,
	.mmap 		= &zc_mmap,
	.owner 		= THIS_MODULE,
};

int avl_init_zc(void)
{
	struct zc_control *ctl = &zc_sniffer;

	memset(ctl, 0, sizeof(*ctl));
	ctl->zc_num = DEFAULT_ZC_NUM;
	init_waitqueue_head(&ctl->zc_wait);
	spin_lock_init(&ctl->zc_lock);
	ctl->zcb = kmalloc(ctl->zc_num * sizeof(struct zc_data), GFP_KERNEL);
	if (!ctl->zcb)
		return -ENOMEM;

	zc_major = register_chrdev(0, zc_name, &zc_ops);
	if (zc_major < 0) {
		printk(KERN_ERR "Failed to register %s char device: err=%d. Zero-copy is disabled.\n",
				zc_name, zc_major);
		return -EINVAL;
	}

	printk(KERN_INFO "Network zero-copy sniffer has been enabled with %d major number.\n", zc_major);

	return 0;
}

void avl_deinit_zc(void)
{
	unregister_chrdev(zc_major, zc_name);
}

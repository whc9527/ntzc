/*
 * 	nta.c
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

#define NSA_DRV_VERSION     "1.00"

MODULE_AUTHOR("Semptian Technologies, <nsa@semptian.com>");
MODULE_DESCRIPTION("Semptian SempGate Network Security Processor (NSA) controller");
MODULE_LICENSE("GPL");
MODULE_VERSION(NSA_DRV_VERSION);

void mbuf_over_panic(struct m_buf *mbuf, int sz, void *here)
{
	printk(KERN_EMERG "mbuf_over_panic: text:%p len:%d put:%d head:%p "
			  "data:%p tail:%#lx end:%#lx dev:%s\n",
	       here, mbuf->len, sz, mbuf->head, mbuf->data,
	       (unsigned long)mbuf->tail, (unsigned long)mbuf->end,
	       mbuf->dev ? mbuf->dev->name : "<NULL>");
	BUG();
}

void mbuf_under_panic(struct m_buf *mbuf, int sz, void *here)
{
	printk(KERN_EMERG "mbuf_under_panic: text:%p len:%d put:%d head:%p "
			  "data:%p tail:%#lx end:%#lx dev:%s\n",
	       here, mbuf->len, sz, mbuf->head, mbuf->data,
	       (unsigned long)mbuf->tail, (unsigned long)mbuf->end,
	       mbuf->dev ? mbuf->dev->name : "<NULL>");
	BUG();
}

EXPORT_SYMBOL(mbuf_put);
EXPORT_SYMBOL(mbuf_pull);

unsigned char *mbuf_put(struct m_buf *mbuf, unsigned int len)
{
	unsigned char *tmp = mbuf_tail_pointer(mbuf);
	mbuf->tail += len;
	mbuf->len  += len;
	if (unlikely(mbuf->tail > mbuf->end))
		mbuf_over_panic(mbuf, len, __builtin_return_address(0));
	return tmp;
}

unsigned char *mbuf_push(struct m_buf *mbuf, unsigned int len)
{
	mbuf->data -= len;
	mbuf->len  += len;
	if (unlikely(mbuf->data<mbuf->head))
		mbuf_under_panic(mbuf, len, __builtin_return_address(0));
	return mbuf->data;
}

unsigned char *mbuf_pull(struct m_buf *mbuf, unsigned int len)
{
	return unlikely(len > mbuf->len) ? NULL : __mbuf_pull(mbuf, len);
}

struct kmem_cache *mbuf_head_cache;


struct m_buf *nta_alloc_mbuf_empty(unsigned int size, gfp_t gfp_mask)
{
	struct m_buf *mbuf;

	/* Get the HEAD */
	mbuf = kmem_cache_alloc(mbuf_head_cache, gfp_mask & ~__GFP_DMA);
	if (!mbuf)
		goto out;

	memset(mbuf, 0, offsetof(struct m_buf, truesize));
	
	mbuf->truesize = size + sizeof(struct m_buf);
	atomic_set(&mbuf->users, 1);

out:
	return mbuf;

}

struct m_buf *__alloc_mbuf(unsigned int size, gfp_t gfp_mask)
{
	struct kmem_cache *cache;
	struct mbuf_shared_info *shinfo;
	struct m_buf *mbuf;
	u8 *data;

	cache = mbuf_head_cache;

	/* Get the HEAD */
	mbuf = kmem_cache_alloc(cache, gfp_mask & ~__GFP_DMA);
	if (!mbuf)
		goto out;

	/* Get the DATA. Size must match mbuf_add_mtu(). */
	size = MBUF_DATA_ALIGN(size);
	data = avl_alloc(size + sizeof(struct mbuf_shared_info), smp_processor_id(), gfp_mask);
	if (!data)
		goto nodata;

	memset(mbuf, 0, offsetof(struct m_buf, truesize));
	mbuf->truesize = size + sizeof(struct m_buf);
	atomic_set(&mbuf->users, 1);
	mbuf->head = data;
	mbuf->data = data;
	mbuf->tail = data;
	mbuf->end  = data + size;
	/* make sure we initialize shinfo sequentially */
	shinfo = mbuf_shinfo(mbuf);
	atomic_set(&shinfo->dataref, 1);
	shinfo->nr_frags  = 0;
	shinfo->gso_size = 0;
	shinfo->gso_segs = 0;
	shinfo->gso_type = 0;
	shinfo->ip6_frag_id = 0;
	shinfo->frag_list = NULL;

out:
	return mbuf;
nodata:
	kmem_cache_free(cache, mbuf);
	mbuf = NULL;
	goto out;
}

EXPORT_SYMBOL(nta_alloc_mbuf);

/**
 *	__netdev_alloc_mbuf - allocate an mbufuff for rx on a specific device
 *	@dev: network device to receive on
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_mbuf
 *
 *	Allocate a new &m_buf and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory.
 */
struct m_buf *nta_alloc_mbuf(struct net_device *dev,
		unsigned int length, gfp_t gfp_mask)
{
	struct m_buf *mbuf;

	mbuf = __alloc_mbuf(length + NET_MBUF_PAD_ALLOC, gfp_mask);
	if (likely(mbuf)) {
		mbuf_reserve(mbuf, NET_MBUF_PAD_ALLOC);
		mbuf->dev = dev;
	}
	return mbuf;
}


static void mbuf_release_data(struct m_buf *mbuf)
{
	struct zc_control *ctl;
	struct zc_sniff	*sniffer;
	int sniff=0;
	u_int16_t p;
	int i;
	
	if (mbuf_shinfo(mbuf)->nr_frags) {
		int i;
		for (i = 0; i < mbuf_shinfo(mbuf)->nr_frags; i++)
			put_page(mbuf_shinfo(mbuf)->frags[i].page);
	}
#if 0
	printk("mbuf->dir %d sniff_mode %d len %d %d\n",
		   mbuf->dir, ctl->sniff_mode[mbuf->nta_index],
		   mbuf->truesize-sizeof(struct m_buf)+sizeof(struct mbuf_shared_info), 
		   mbuf->end - mbuf->head + sizeof(struct mbuf_shared_info));
#endif
	for(i=0; i< ZC_MAX_SNIFFERS; i++){
		ctl = &zc_sniffer[i];
		if(!ctl->bind) {
			continue;
		}
		/* more sniffering conditions can be here */
		sniffer = &ctl->sniffer[mbuf->nta_index];
		if((mbuf->dir & sniffer->dev_index)){
			p = sniffer->pre_p;
			if(!p) {
				sniff &= (1<<i);
			}else{
				if(p == mbuf->protocol) {
					if(p == ZC_PRE_P_NPCP) {
						switch (sniffer->pre_type) {
						case ZC_PRE_P_ALL:
							sniff |= (1<<i);
							break;
						case ZC_PRE_P_CONRTOL:
							if( (mbuf->data[3] & 0xf0) == ZC_PRE_P_CONRTOL)
								sniff |= (1<<i);
							break;
						case ZC_PRE_P_PACKET:
							if((mbuf->data[3] == ZC_PRE_P_PACKET) && (mbuf->data[4]&0xf0)==1) {
								sniff |= (1<<i);
							}
							break;
						case ZC_PRE_P_SESSION:
							if((mbuf->data[3] == ZC_PRE_P_PACKET) && (mbuf->data[4]&0xf0)!=1) {
								sniff |= (1<<i);
							}
						default:
							sniff |= (0<<i);
						}
					}else
						sniff |= (1<<i);
				}
			}
		}
	}
	
	avl_free(mbuf->head, sniff, mbuf->truesize-sizeof(struct m_buf)+ sizeof(struct mbuf_shared_info), mbuf->len);
}


void __kfree_mbuf(struct m_buf *mbuf)
{
	mbuf_release_data(mbuf);
	kmem_cache_free(mbuf_head_cache, mbuf);
}

EXPORT_SYMBOL(nta_kfree_mbuf);

void nta_kfree_mbuf(struct m_buf *mbuf)
{
	if (unlikely(!mbuf))
		return;
	if (likely(atomic_read(&mbuf->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&mbuf->users)))
		return;
	__kfree_mbuf(mbuf);
}


int mbuf_dma_map(struct device *dev, struct m_buf *mbuf,
		enum dma_data_direction dir)
{
	struct mbuf_shared_info *sp = mbuf_shinfo(mbuf);
	dma_addr_t map;
	int i;

	map = dma_map_single(dev, mbuf->data,
			     mbuf_headlen(mbuf), dir);
	if (dma_mapping_error(dev, map))
		goto out_err;

	sp->dma_maps[0] = map;
	for (i = 0; i < sp->nr_frags; i++) {
		mbuf_frag_t *fp = &sp->frags[i];

		map = dma_map_page(dev, fp->page, fp->page_offset,
				   fp->size, dir);
		if (dma_mapping_error(dev, map))
			goto unwind;
		sp->dma_maps[i + 1] = map;
	}
	sp->num_dma_maps = i + 1;

	return 0;

unwind:
	while (--i >= 0) {
		mbuf_frag_t *fp = &sp->frags[i];

		dma_unmap_page(dev, sp->dma_maps[i + 1],
			       fp->size, dir);
	}
	dma_unmap_single(dev, sp->dma_maps[0],
			 mbuf_headlen(mbuf), dir);
out_err:
	return -ENOMEM;
}
EXPORT_SYMBOL(mbuf_dma_map);

void mbuf_dma_unmap(struct device *dev, struct m_buf *mbuf,
		   enum dma_data_direction dir)
{
	struct mbuf_shared_info *sp = mbuf_shinfo(mbuf);
	int i;

	dma_unmap_single(dev, sp->dma_maps[0],
			 mbuf_headlen(mbuf), dir);
	for (i = 0; i < sp->nr_frags; i++) {
		mbuf_frag_t *fp = &sp->frags[i];

		dma_unmap_page(dev, sp->dma_maps[i + 1],
			       fp->size, dir);
	}
}
EXPORT_SYMBOL(mbuf_dma_unmap);

EXPORT_SYMBOL(nta_register_zc);

int nta_register_zc(struct net_device *netdev,
					int	(*hard_start_xmit) (struct m_buf *mbuf,
							    struct net_device *dev))
{
	int i;
	struct zc_control *zc = &zc_sniffer[0];
	for(i=0; i< ZC_MAX_NETDEVS; i++) {
		//printk("zc->netdev[%d] %p\n", i, zc->netdev[i]);
		if(!zc->netdev[i]){
			zc->netdev[i] = netdev;
			zc->hard_start_xmit = hard_start_xmit;
			return i;
		}
	}
	return -1;
}


static struct timer_list test_timer;
static unsigned long count_a, count_b[2];
struct sig{
	unsigned long count;
	unsigned long stamp;
};


	
static void nta_test_func(unsigned long data)
{
	int i;
	struct sig *sig;
	struct m_buf *mbuf;

	for(i=0; i<4096;i++) {
		mbuf = nta_alloc_mbuf(NULL, 1522, GFP_ATOMIC);
		if(!mbuf) {
			continue;
		}
		mbuf->len = 256;
		mbuf->dir = NTA_DIR_RX;

		sig = (struct sig*)mbuf->data;
		sig->count = count_a;
		sig->stamp = jiffies;
		count_a++;
		nta_kfree_mbuf(mbuf);
	}
	mod_timer(&test_timer, jiffies+1);
}


static int nta_counter_show(struct seq_file *seq, void *v)
{
	struct zc_control *ctl = &zc_sniffer[0];

	seq_printf(seq, "Network Tree Zero Copy statistics:\n");
	seq_printf(seq, "\tcounter[0]: alloc %lu free %lu hook %lu unhook %lu update %lu miss %lu cache %lu full %lu\n", 
		   count_alloc[0], count_free[0], count_hook[0], count_unhook[0], count_update[0], count_miss[0],
			   count_cache[0], count_full[0]);
	seq_printf(seq, "\tcounter[1]: alloc %lu free %lu hook %lu unhook %lu update %lu miss %lu cache %lu full %lu\n", 
		   count_alloc[1], count_free[1], count_hook[1], count_unhook[1], count_update[1], count_miss[1],
			   count_cache[1], count_full[1]);
	seq_printf(seq, "\tcount_a: %lu count_b[0,1]: %lu %lu\n",
			   count_a, count_b[0], count_b[1]);
	seq_printf(seq, "Sniffer information:\n");
	seq_printf(seq, "\tzc_num: %u zc_used %u zc_pos %u zc_max %u\n",
			   ctl->zc_num, ctl->zc_used, ctl->zc_pos, ctl->zc_max);

	seq_printf(seq, "\tcount_page %lu\n", count_page);
	seq_printf(seq, "\tcount_node [%lu %lu]\tcount_mem[%lu %lu]\n", 
			   count_node[0], count_node[1], count_mem[0], count_mem[1]);

	return 0;
}

static int nta_counter_open(struct inode *inode, struct file *file)
{
	return single_open(file, nta_counter_show, PDE(inode)->data);
}

static const struct file_operations nta_counter_fps = {
	.owner		= THIS_MODULE,
	.open       = nta_counter_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release	= single_release,
};

int nta_proc_init(void)
{
	struct proc_dir_entry *res;
	res = create_proc_entry("ntzc", 0666, NULL);
	if (!res)
		return -ENOMEM;
	res->proc_fops = &nta_counter_fps;

	return 0;
}	


int nta_proc_deinit(void)
{
	remove_proc_entry("ntzc", NULL);
	return 0;
}

static int __init
nta_init_module(void)
{
	int i;
	unsigned long j1, j2, interval1, interval2;
	int count = 0;

	mbuf_head_cache = kmem_cache_create("mbuf_head_cache",
					      sizeof(struct m_buf),
					      0,
					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					      NULL);

	if(!mbuf_head_cache) {
		printk(KERN_ERR "Unable to allocate mbuf head cache.\n");
		return -1;
	}

	if (avl_init())
		panic("Failed to initialize network tree allocator.\n");

	j1 = jiffies;
	for(i=0; i<count; i++) {
		struct sk_buff * skb;
		skb = netdev_alloc_skb(NULL, BVL_MEM_SIZE);
		kfree_skb(skb);
	}
	interval1 = (long)get_jiffies_64() - j1;
	printk("mbuf alloc and free performance: %lu jiffies for %d mbufs\n", interval1, count);
	
	j2 = jiffies;
	for(i=0; i<count; i++) {
		struct m_buf * mbuf;
		mbuf = nta_alloc_mbuf(NULL, BVL_MBUF_LEN, GFP_ATOMIC);
		nta_kfree_mbuf(mbuf);
	}
	interval2 = (long)get_jiffies_64() - j2;
	printk("mbuf alloc and free performance: %lu jiffies for %d mbufs\n", interval2, count);

	nta_proc_init();

#if 0
	test_timer.function = &nta_test_func;
	init_timer(&test_timer);
	count_a = 0ul;
	count_b[0] = count_b[1] = 0ul;

	mod_timer(&test_timer, jiffies+1);
#endif
	return 0;
}

module_init(nta_init_module);


static void __exit
nta_exit_module(void)
{
	del_timer(&test_timer);
	nta_proc_deinit();
	avl_deinit_zc();
	kmem_cache_destroy(mbuf_head_cache);

	printk(KERN_INFO "nta driver exit\n");
}

module_exit(nta_exit_module);


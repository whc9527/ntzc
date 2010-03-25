/*
 * 	bvl.h
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


#ifndef __BVL_H
#define __BVL_H

#ifndef IFNAMSIZ
#define	IFNAMSIZ	16
#endif

struct m_buf;
/*
 * Zero-copy allocation control block.
 * @ptr - pointer to allocated data.
 * @off - offset inside given @avl_node_entry pages (absolute number of bytes)
 * @size - size of the appropriate object
 * @entry - number of @avl_node_entry which holds allocated object
 */

struct zc_data
{
	union {
		__u32		data[2];
		void		*ptr;
	} data;

	__u32			off;
	__u16			s_size;  /* the chunk size */
	__u16			r_size;  /* the packet size */

	__u16			entry;
	__u8			cpu;
	__u8			netdev_index;
};

#define ZC_MAX_ENTRY_NUM	170

/*
 * Zero-copy allocation request.
 * @type - type of the message - ipv4/ipv6/...
 * @res_len - length of reserved area at the beginning.
 * @data - allocation control block.
 */
struct zc_alloc_ctl
{
	__u16		proto;
	__u16		res_len;
	struct zc_data	zc;
};

struct zc_entry_status
{
	__u16		node_order, node_num;
};

struct zc_status
{
	unsigned int	entry_num;
	struct zc_entry_status	entry[ZC_MAX_ENTRY_NUM];
};

struct zc_netdev
{
	char dev_name[IFNAMSIZ];
	int index;
};

struct zc_sniff
{
	int sniff_id;
	int dev_index;
	int sniff_mode;
#define ZC_SNIFF_NONE		0
#define ZC_SNIFF_RX			1
#define ZC_SNIFF_TX			2
#define ZC_SNIFF_ALL		3
	u_int16_t	pre_p;		
#define ZC_PRE_P_NPCP		0x8050
#define ZC_PRE_P_NORMAL		0
	u_int16_t	pre_type;
#define ZC_PRE_P_ALL		0
#define ZC_PRE_P_CONRTOL	0x20
#define ZC_PRE_P_PACKET		0x10
#define ZC_PRE_P_SESSION	0x11

	u_int32_t acl_index;
	
};

#define ZC_ALLOC			_IOWR('Z', 1, struct zc_alloc_ctl)
#define ZC_COMMIT			_IOR('Z', 2, struct zc_alloc_ctl)
#define ZC_SET_CPU			_IOR('Z', 3, int)
#define ZC_STATUS			_IOWR('Z', 4, struct zc_status)
#define ZC_SET_SNIFF		_IOWR('Z', 5, struct zc_sniff)
#define ZC_GET_NETDEV		_IOWR('Z', 6, struct zc_netdev)
#define ZC_ENABLE_SNIFF		_IOR('Z', 7, int)
#define ZC_DISABLE_SNIFF	_IOR('Z', 8, int)
#define BVL_ORDER		2	/* Maximum allocation order */
#define BVL_BITS		7	/* Must cover maximum number of pages used for allocation pools */

#define DEFAULT_ZC_NUM	16384
#define BVL_MAX_NODE_ENTRY_NUM	3

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <asm/page.h>

//#define BVL_DEBUG

#ifdef BVL_DEBUG
#define ulog(f, a...) printk(f, ##a)
#else
#define ulog(f, a...)
#endif

/*
 * Network tree allocator variables.
 */

#define BVL_CANARY			0xc0d0e0f0
#define BVL_UNUSE_MAGIC		0xceaddead

#define BVL_ALIGN_SIZE		L1_CACHE_BYTES
#define BVL_ALIGN(x) 		ALIGN(x, BVL_ALIGN_SIZE)

#define BVL_NODES_ON_PAGE	(PAGE_SIZE/sizeof(struct avl_node))
#define BVL_NODE_NUM		(1UL<<BVL_BITS)
#define BVL_NODE_PAGES		((BVL_NODE_NUM+BVL_NODES_ON_PAGE-1)/BVL_NODES_ON_PAGE)

#define BVL_CELL_SIZE		2048
#define BVL_MEM_SIZE		(BVL_CELL_SIZE-sizeof(struct avl_chunk))
#define BVL_MBUF_LEN        1664

struct avl_node_entry;

/*
 * Meta-information container for each contiguous block used in allocation.
 * @value - start address of the contiguous block.
 * @mask - bitmask of free and empty chunks [1 - free, 0 - used].
 * @entry - pointer to parent node entry.
 */
struct avl_node
{
	unsigned long		value;
	struct avl_node_entry	*entry;
};

/*
 * Each array of nodes is places into dynamically grown list.
 * @avl_node_array - array of nodes (linked into pages)
 * @node_entry - entry in avl_allocator_data.avl_node_list.
 * @avl_node_order - allocation order for each node in @avl_node_array
 * @avl_node_num - number of nodes in @avl_node_array
 * @avl_entry_num - number of this entry inside allocator
 */

struct avl_node_entry
{
	struct avl_node 	**avl_node_array;
	struct list_head	node_entry;
	u32		avl_entry_num;
	u16 	avl_node_order, avl_node_num;
};


/*
 * When freeing happens on different than allocation CPU,
 * chunk is dereferenced into this structure and placed into
 * single-linked list in allocation CPU private area.
 */

struct avl_free_list
{
	struct avl_free_list		*next;
	unsigned int			size;
	unsigned int			cpu;
};

/*
 * This structure is placed after each allocated chunk and contains
 * @canary - used to check memory overflow and reference counter for
 * given memory region, which is used for example for zero-copy access.
 * @size - used to check that freeing size is exactly the size of the object.
 */

struct avl_chunk
{
	unsigned int			canary, size;
	atomic_t			refcnt;
};

/*
 * Main per-cpu allocator structure.
 * @avl_container_array - array of lists of free chunks indexed by size of the elements
 * @avl_free_list_head - single-linked list of objects, which were started to be freed on different CPU
 * @avl_free_lock - lock protecting avl_free_list_head
 * @avl_node_list - list of avl_node_entry'es
 * @avl_node_lock - lock used to protect avl_node_list from access from zero-copy devices.
 * @entry_num - number of entries inside allocator.
 */
struct avl_allocator_data
{
	struct avl_free_list 	*avl_free_list_head;
	spinlock_t 		avl_free_lock;
	struct list_head 	avl_node_list;
	spinlock_t 		avl_node_lock;
	u32			avl_node_entry_num;
};





void *avl_alloc(unsigned int size, int cpu, gfp_t gfp_mask);
void avl_free(void *ptr, int dir, int size, int r_size);
int avl_init(void);

void avl_free_no_zc(void *ptr, unsigned int size);

int avl_init_zc(void);
void avl_deinit_zc(void);
void avl_fill_zc(struct zc_data *zc, void *ptr, unsigned int size, int r_size);

#define ZC_MAX_NETDEVS		8
#define ZC_MAX_SNIFFERS		3

struct zc_control
{
	int bind;

	struct zc_data		*zcb;
	unsigned int		zc_num, zc_used, zc_pos, zc_max;
	
	struct zc_sniff 	sniffer[ZC_MAX_NETDEVS];
	struct net_device*	netdev[ZC_MAX_NETDEVS];
	int		(*hard_start_xmit) (struct m_buf *mbuf,
							struct net_device *dev);

	spinlock_t		zc_lock;
	wait_queue_head_t	zc_wait;
};

extern struct zc_control zc_sniffer[ZC_MAX_SNIFFERS];
extern struct avl_allocator_data avl_allocator[NR_CPUS];


extern unsigned long 
	count_alloc[NR_CPUS], count_free[NR_CPUS], 
	count_hook[NR_CPUS], count_unhook[NR_CPUS],
	count_update[NR_CPUS], count_miss[NR_CPUS],
	count_cache[NR_CPUS], count_full[NR_CPUS],
	count_node[NR_CPUS], count_mem[NR_CPUS],
	count_page;

#endif /* __KERNEL__ */
#endif /* __BVL_H */


#ifndef _ZC_COMMON_H
#define _ZC_COMMON_H

#ifndef __KERNEL__
#include <linux/types.h>
#include <sys/user.h>
#include <net/if.h>
#else
#include <linux/if.h>
#include <asm/page.h>
#endif
/* zc_data should always be mod==0 by 4096 */

struct zc_data
{
	union {
		__u32		data[2];
		void		*ptr;
	} data;
	__u32			off;
	__u16			r_size;  /* the packet size */
	__u8			entry;
	__u8			cpu:4, netdev_index:4;
};

#define ZC_MAX_ENTRY_NUM	170

struct zc_ring
{
	__u16 zc_pos;
	__u16 zc_used;
};

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

#define ZC_MAX_NETDEVS		8
#define ZC_MAX_SNIFFERS		4

#define DEFAULT_ZC_NUM	16384
#define BVL_MAX_NODE_ENTRY_NUM	20

#define SNIFFER_RING_PAGES 1024
#define SNIFFER_RING_NODES	(SNIFFER_RING_PAGES*(PAGE_SIZE/sizeof(struct zc_data)/ZC_MAX_SNIFFERS))

#define NTA_NR_CPUS			2

#endif /* _ZC_COMMON_H */


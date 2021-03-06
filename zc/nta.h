/*
 * 	nta.h
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

#ifndef _NTA_H
#define _NTA_H

#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/time.h>
#include <linux/cache.h>

#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/net.h>
#include <net/checksum.h>
#include <linux/rcupdate.h>
#include <linux/dmaengine.h>

#define MBUF_DATA_ALIGN(X)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))

#define NET_MBUF_PAD_ALLOC	64

typedef unsigned char *m_buf_data_t;
#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

struct m_buf {
	/* These two members must be first. */
	struct m_buf		*next;
	struct m_buf		*prev;

	struct sock		*sk;
	//ktime_t			tstamp;
	struct net_device	*dev;

	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a mbuf_clone()
	 * first. This is owned by whoever has the mbuf queued ATM.
	 */
	char			cb[48];

	unsigned int		len,
				data_len;
	__u16			mac_len,
				hdr_len;
	union {
		__wsum		csum;
		struct {
			__u16	csum_start;
			__u16	csum_offset;
		};
	};
	__u32			priority;
	__u8			local_df:1,
				cloned:1,
				ip_summed:2,
				nohdr:1,
				nfctinfo:3;
	__u8			pkt_type:3,
				fclone:2,
				ipvs_property:1,
				peeked:1,
				nf_trace:1;
	__be16			protocol;

	void			(*destructor)(struct m_buf *mbuf);
	
	int			iif;
	__u16			queue_mapping;

	__u32			mark;

	__u16			vlan_tci;

	__u8		nta_index;
	__u8		dir;
	__u16 		sniff;


	m_buf_data_t		transport_header;
	m_buf_data_t		network_header;
	m_buf_data_t		mac_header;
	/* These elements must be at the end, see alloc_mbuf() for details.  */
	m_buf_data_t		tail;
	m_buf_data_t		end;
	unsigned char		*head,
				*data;

	unsigned int		truesize;

	atomic_t		users;
};

/* To allow 64K frame to be packed as single mbuf without frag_list */
#define MAX_MBUF_FRAGS (2)

typedef struct mbuf_frag_struct mbuf_frag_t;

struct mbuf_frag_struct {
	struct page *page;
	__u32 page_offset;
	__u32 size;
};

#define HAVE_HW_TIME_STAMP

/**
 * struct mbuf_shared_hwtstamps - hardware time stamps
 * @hwtstamp:	hardware time stamp transformed into duration
 *		since arbitrary point in time
 * @syststamp:	hwtstamp transformed to system time base
 *
 * Software time stamps generated by ktime_get_real() are stored in
 * mbuf->tstamp. The relation between the different kinds of time
 * stamps is as follows:
 *
 * syststamp and tstamp can be compared against each other in
 * arbitrary combinations.  The accuracy of a
 * syststamp/tstamp/"syststamp from other device" comparison is
 * limited by the accuracy of the transformation into system time
 * base. This depends on the device driver and its underlying
 * hardware.
 *
 * hwtstamps can only be compared against other hwtstamps from
 * the same device.
 *
 * This structure is attached to packets as part of the
 * &mbuf_shared_info. Use mbuf_hwtstamps() to get a pointer.
 */
#if 0
struct mbuf_shared_hwtstamps {
	ktime_t	hwtstamp;
	ktime_t	syststamp;
};
#endif
/**
 * struct mbuf_shared_tx - instructions for time stamping of outgoing packets
 * @hardware:		generate hardware time stamp
 * @software:		generate software time stamp
 * @in_progress:	device driver is going to provide
 *			hardware time stamp
 * @flags:		all shared_tx flags
 *
 * These flags are attached to packets as part of the
 * &mbuf_shared_info. Use mbuf_tx() to get a pointer.
 */
union mbuf_shared_tx {
	struct {
		__u8	hardware:1,
			software:1,
			in_progress:1;
	};
	__u8 flags;
};

struct mbuf_shared_info {
	atomic_t	dataref;
	unsigned short	nr_frags;
	unsigned short	gso_size;
	/* Warning: this field is not always filled in (UFO)! */
	unsigned short	gso_segs;
	unsigned short  gso_type;
	__be32          ip6_frag_id;
	union mbuf_shared_tx tx_flags;
	unsigned int	num_dma_maps;
	struct m_buf	*frag_list;
	//struct mbuf_shared_hwtstamps hwtstamps;
	mbuf_frag_t	frags[MAX_MBUF_FRAGS];
	dma_addr_t	dma_maps[MAX_MBUF_FRAGS + 1];
};

static inline unsigned char *mbuf_end_pointer(const struct m_buf *mbuf)
{
	return mbuf->end;
}

/* Internal */
#define mbuf_shinfo(MBUF)	((struct mbuf_shared_info *)(mbuf_end_pointer(MBUF)))

static inline void mbuf_reserve(struct m_buf *mbuf, int len)
{
	mbuf->data += len;
	mbuf->tail += len;
}

static inline unsigned char *mbuf_tail_pointer(const struct m_buf *mbuf)
{
	return mbuf->tail;
}

static inline void mbuf_reset_tail_pointer(struct m_buf *mbuf)
{
	mbuf->tail = mbuf->data;
}

static inline void mbuf_set_tail_pointer(struct m_buf *mbuf, const int offset)
{
	mbuf->tail = mbuf->data + offset;
}


/*
 *	Add data to an m_buf
 */
extern unsigned char *mbuf_put(struct m_buf *mbuf, unsigned int len);
static inline unsigned char *__mbuf_put(struct m_buf *mbuf, unsigned int len)
{
	unsigned char *tmp = mbuf_tail_pointer(mbuf);
	mbuf->tail += len;
	mbuf->len  += len;
	return tmp;
}

extern unsigned char *mbuf_push(struct m_buf *mbuf, unsigned int len);
static inline unsigned char *__mbuf_push(struct m_buf *mbuf, unsigned int len)
{
	mbuf->data -= len;
	mbuf->len  += len;
	return mbuf->data;
}

extern unsigned char *mbuf_pull(struct m_buf *mbuf, unsigned int len);
static inline unsigned char *__mbuf_pull(struct m_buf *mbuf, unsigned int len)
{
	mbuf->len -= len;
	BUG_ON(mbuf->len < mbuf->data_len);
	return mbuf->data += len;
}


static inline void mbuf_copy_to_linear_data(struct m_buf *mbuf,
					   const void *from,
					   const unsigned int len)
{
	memcpy(mbuf->data, from, len);
}

static inline unsigned int mbuf_headlen(const struct m_buf *mbuf)
{
	return mbuf->len - mbuf->data_len;
}

#if 0
static inline struct mbuf_shared_hwtstamps *mbuf_hwtstamps(struct m_buf *mbuf)
{
	return &mbuf_shinfo(mbuf)->hwtstamps;
}
#endif
static inline union mbuf_shared_tx *mbuf_tx(struct m_buf *mbuf)
{
	return &mbuf_shinfo(mbuf)->tx_flags;
}

static inline unsigned char *mbuf_transport_header(const struct m_buf *mbuf)
{
	return mbuf->transport_header;
}

static inline void mbuf_reset_transport_header(struct m_buf *mbuf)
{
	mbuf->transport_header = mbuf->data;
}

static inline void mbuf_set_transport_header(struct m_buf *mbuf,
					    const int offset)
{
	mbuf->transport_header = mbuf->data + offset;
}

static inline unsigned char *mbuf_network_header(const struct m_buf *mbuf)
{
	return mbuf->network_header;
}

static inline void mbuf_reset_network_header(struct m_buf *mbuf)
{
	mbuf->network_header = mbuf->data;
}

static inline void mbuf_set_network_header(struct m_buf *mbuf, const int offset)
{
	mbuf->network_header = mbuf->data + offset;
}

static inline unsigned char *mbuf_mac_header(const struct m_buf *mbuf)
{
	return mbuf->mac_header;
}

static inline int mbuf_mac_header_was_set(const struct m_buf *mbuf)
{
	return mbuf->mac_header != NULL;
}

static inline void mbuf_reset_mac_header(struct m_buf *mbuf)
{
	mbuf->mac_header = mbuf->data;
}

static inline void mbuf_set_mac_header(struct m_buf *mbuf, const int offset)
{
	mbuf->mac_header = mbuf->data + offset;
}

static inline int mbuf_transport_offset(const struct m_buf *mbuf)
{
	return mbuf_transport_header(mbuf) - mbuf->data;
}

static inline u32 mbuf_network_header_len(const struct m_buf *mbuf)
{
	return mbuf->transport_header - mbuf->network_header;
}

static inline int mbuf_network_offset(const struct m_buf *mbuf)
{
	return mbuf_network_header(mbuf) - mbuf->data;
}

static inline void mbuf_set_queue_mapping(struct m_buf *mbuf, u16 queue_mapping)
{
	mbuf->queue_mapping = queue_mapping;
}

static inline u16 mbuf_get_queue_mapping(const struct m_buf *mbuf)
{
	return mbuf->queue_mapping;
}

static inline void mbuf_copy_queue_mapping(struct m_buf *to, const struct m_buf *from)
{
	to->queue_mapping = from->queue_mapping;
}

static inline void mbuf_record_rx_queue(struct m_buf *mbuf, u16 rx_queue)
{
	mbuf->queue_mapping = rx_queue + 1;
}

static inline u16 mbuf_get_rx_queue(const struct m_buf *mbuf)
{
	return mbuf->queue_mapping - 1;
}

static inline bool mbuf_rx_queue_recorded(const struct m_buf *mbuf)
{
	return (mbuf->queue_mapping != 0);
}


static inline void mbuf_copy_from_linear_data_offset(const struct m_buf *mbuf,
						    const int offset, void *to,
						    const unsigned int len)
{
	memcpy(to, mbuf->data + offset, len);
}

extern struct m_buf *nta_alloc_mbuf_empty(unsigned int size, gfp_t gfp_mask);
extern struct m_buf *nta_alloc_mbuf(struct net_device *dev, unsigned int length, gfp_t gfp_mask);
extern void nta_kfree_mbuf(struct m_buf *mbuf);
extern int nta_register_zc(struct net_device *netdev,
					int	(*hard_start_xmit) (struct m_buf *mbuf,
							    struct net_device *dev));


#define NTA_DIR_RX		1
#define NTA_DIR_TX		2

#endif /* _NTA_H */

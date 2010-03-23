/*
 * 	control.h	
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

#ifndef __INT_H
#define __INT_H

#define PAGE_SIZE	4096

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

#define DEFAULT_ZC_NUM	16384
#define ZC_MAX_ENTRY_NUM	170

struct zc_control
{
	int		cpu;
	int		fd;
	unsigned int	offset;
	struct zc_data	node_entries[ZC_MAX_ENTRY_NUM];
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
	int dev_index;
	int sniff_mode;
#define ZC_SNIFF_NONE		0
#define ZC_SNIFF_RX			1
#define ZC_SNIFF_TX			2
#define ZC_SNIFF_ALL		3
};

#define ZC_ALLOC			_IOWR('Z', 1, struct zc_alloc_ctl)
#define ZC_COMMIT			_IOR('Z', 2, struct zc_alloc_ctl)
#define ZC_SET_CPU			_IOR('Z', 3, int)
#define ZC_STATUS			_IOWR('Z', 4, struct zc_status)
#define ZC_SET_SNIFF		_IOWR('Z', 5, struct zc_sniff)
#define ZC_GET_NETDEV		_IOWR('Z', 6, struct zc_netdev)


struct zc_control *zc_ctl_init(int nr_cpus, char *ctl_file);
void zc_ctl_shutdown(struct zc_control *zc);

int zc_ctl_prepare_polling(struct zc_control **zc_ctl, unsigned int nr_cpus);
int zc_recv_loop(struct zc_control **zc_ctl, 
				 unsigned int nr_cpus, char *param,
				 void (*zc_analyze)(void *ptr, int length, char *param));

void * zc_alloc_buffer(struct zc_control *ctl,
                       struct zc_alloc_ctl *alloc_ctl);
int zc_commit_buffer(struct zc_control *ctl, struct zc_alloc_ctl *alloc_ctl);

int zc_ctl_set_sniff(struct zc_control *zc, int dev_index, int mode);
int zc_ctl_get_devid(struct zc_control *zc, char *dev_name);

#endif /* __INT_H */

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

#include "../zc/zc_comm.h"

struct zc_user_control
{
	int		cpu;
	int		fd;
	unsigned int	offset;
	int 	sniffer_id;
	int 	ring_num;
	struct zc_data	node_entries[ZC_MAX_ENTRY_NUM];
};

struct zc_user_control *zc_ctl_init(int nr_cpus, char *ctl_file);
void zc_ctl_shutdown(struct zc_user_control *zc);

int zc_ctl_prepare_polling(struct zc_user_control **zc_ctl, unsigned int nr_cpus);
int zc_recv_loop(struct zc_user_control **zc_ctl, 
				 unsigned int nr_cpus, char *param,
				 void (*zc_analyze)(void *ptr, int length, char *param));

void * zc_alloc_buffer(struct zc_user_control *ctl,
                       struct zc_alloc_ctl *alloc_ctl);
int zc_commit_buffer(struct zc_user_control *ctl, struct zc_alloc_ctl *alloc_ctl);

int zc_ctl_set_sniff(struct zc_user_control *zc, struct zc_sniff *zs);
int zc_ctl_get_devid(struct zc_user_control *zc, char *dev_name);

struct zc_pool{
	char *_pool[DEFAULT_ZC_NUM];
	unsigned int _len[DEFAULT_ZC_NUM];
	int num;
	struct zc_ring ring_rec[NTA_NR_CPUS];
};

int zc_save_into_pool(struct zc_user_control **zc_ctl, 
				 unsigned int nr_cpus,
				 struct zc_pool *pool);

int zc_release_pool(struct zc_user_control **zc_ctl, 
				 unsigned int nr_cpus,
				 struct zc_pool *pool);

int zc_ctl_enable_sniff(struct zc_user_control *zc, int enable, int id);


#endif /* __INT_H */

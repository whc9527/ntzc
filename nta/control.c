/*
 * 	control.c
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

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>

#include <netinet/ip.h>

#include <linux/types.h>
#include <linux/if.h>

#include "control.h"

#define dump_skb(s, p, l) \
do {\
    int i;\
    printf("\n%s %s packet: \n", __FUNCTION__, s);\
    for(i=0; i<l; i++) {\
		printf("%02x ", p[i]&0xff); \
        if((i+1)%8==0) {\
            printf( "\n");\
        }\
    } \
    printf( "\n"); \
}while(0)


static struct zc_data *zcb[ZC_MAX_SNIFFERS];

static int zc_mmap(struct zc_user_control *ctl, struct zc_status *st)
{
	struct zc_data *e;
	unsigned int entry_num = st->entry_num;
	int i;

	printf("entry_num = %d\n", entry_num);
	for (i=0; i<entry_num; ++i) {
		struct zc_entry_status *ent = &st->entry[i];

		e = &ctl->node_entries[i];

		if (e->data.ptr || !ent->node_num)
			continue;

		e->data.ptr = mmap(NULL, PAGE_SIZE*(1<<ent->node_order)*ent->node_num, PROT_READ|PROT_WRITE, MAP_SHARED, ctl->fd, i*PAGE_SIZE);
		if (e->data.ptr == MAP_FAILED) {
			fprintf(stderr, "Failed to mmap: mmap: %2d.%2d: cpu: %d number: %u, order: %u, offset: %u, errno: %d - %s.\n", 
					i, st->entry_num, ctl->cpu, ent->node_num, ent->node_order, ctl->offset, errno, strerror(errno));
			e->data.ptr = NULL;
			return -1;
		}

		printf("mmap: %2d.%2d: cpu: %d, ptr: %p, number: %u, order: %u, offset: %u.\n", 
				i, st->entry_num, ctl->cpu, e->data.ptr, ent->node_num, ent->node_order, ctl->offset);
		ctl->offset += (1<<ent->node_order)*ent->node_num;
		e->entry = i;
		if(i==(entry_num-1)) {
			int j;
			for(j=0; j<ZC_MAX_SNIFFERS; j++){
				zcb[j] = (struct zc_data*)(e->data.ptr+j*ctl->ring_num*sizeof(struct zc_data));
				printf("mmap ring zone: zcb[%d] %p entry %p\n", j, zcb[j], e->data.ptr);
			}
		}
	}

	return 0;
}

static int zc_prepare(struct zc_user_control *ctl)//, unsigned int entry_num)
{
	int err;
	struct zc_status st;

	memset(&st, 0, sizeof(struct zc_status));
	st.entry_num = 0;
	err = ioctl(ctl->fd, ZC_STATUS, &st);
	if (err) {
		fprintf(stderr, "Failed to get status for CPU%d: %s [%d].\n", 
				ctl->cpu, strerror(errno), errno);
		return err;
	}

	err = zc_mmap(ctl,  &st);
	if (err)
		return err;
	return 0;
}

int zc_ctl_set_sniff(struct zc_user_control *zc, struct zc_sniff *zs)
{
	int err;

	err = ioctl(zc->fd, ZC_SET_SNIFF, zs);
	if(err) {
		perror("Failed to setup sniff mode: ");
		return err;
	}
	return 0;
}

int zc_ctl_enable_sniff(struct zc_user_control *zc, int enable, int id)
{
	int err;
	int command = enable? ZC_ENABLE_SNIFF: ZC_DISABLE_SNIFF;

	zc->sniffer_id = id;
	err = ioctl(zc->fd, command, &id);

	return err;

}

int zc_ctl_get_devid(struct zc_user_control *zc, char *dev_name)
{
	int err;
	struct zc_netdev zn;

	strncpy(zn.dev_name, dev_name, 8);

	err = ioctl(zc->fd, ZC_GET_NETDEV, &zn);
	if(err) {
		fprintf(stderr, "Failed to get dev %s index.\n", dev_name);
		return err;
	}
	return zn.index;
}

static char default_ctl_file[] = "/dev/zc";

struct zc_user_control *zc_ctl_init(int cpu_id, char *ctl_file)
{
	int err;
	struct zc_user_control  *ctl;

    if(!ctl_file) {
        ctl_file = default_ctl_file;
    }
	ctl = malloc(sizeof(struct zc_user_control));

	if (!ctl) {
		fprintf(stderr, "Failed to allocate control structures for CPU %d.\n", cpu_id);
		return NULL;
	}

	memset(ctl, 0, sizeof(struct zc_user_control));

	do {
		ctl->cpu = cpu_id; 
		ctl->fd = open(ctl_file, O_RDWR);
		if (!ctl->fd) {
			fprintf(stderr, "Failed to open control file %s: %s [%d].\n", ctl_file, strerror(errno), errno);
			return NULL;
		}

		err = ioctl(ctl->fd, ZC_SET_CPU, &ctl->cpu);
		if (err) {
			close(ctl->fd);
			fprintf(stderr, "Failed to setup CPU %d.\n", ctl->cpu);
			return NULL;
		}
		ctl->ring_num = SNIFFER_RING_NODES/ZC_MAX_SNIFFERS;
		if (zc_prepare(ctl)){
			close(ctl->fd);
			fprintf(stderr, "Failed to prepare CPU%d.\n", ctl->cpu);
			return NULL;
		}
	}while(0);

	return ctl;
}

struct pollfd *_pfd;
int zc_ctl_prepare_polling(struct zc_user_control **zc_ctl, unsigned int nr_cpus)
{
    int i;
    if(_pfd) {
        fprintf(stderr, "polling already setupped\n");
        return -1;
    }
	_pfd = malloc(sizeof(struct pollfd) * nr_cpus);
	if (!_pfd) {
		fprintf(stderr, "Failed to allocate polling structures for %d cpus.\n", nr_cpus);
		return -2;
	}
	memset(_pfd, 0, sizeof(struct pollfd) * nr_cpus);

	for (i=0; i<nr_cpus; ++i) {
		_pfd[i].fd = zc_ctl[i]->fd;
		_pfd[i].events = POLLIN;
		_pfd[i].revents = 0;
	}
	return 0;
}

int zc_recv_loop(struct zc_user_control **zc_ctl, 
				 unsigned int nr_cpus,
				 char * param,
				 void (*zc_analyze)(void *ptr, int length, char *param))
{
		int poll_ready, i, j, pos;
		int err;
		unsigned int num, t_num=0;
		struct zc_ring ring;
		struct zc_data *zcr;

		poll_ready = poll(_pfd, nr_cpus, 1000);
		if (poll_ready == 0){
			return 0;
		}
		if (poll_ready < 0)
			return -1;

		for (j=0; j<poll_ready; ++j) {
			if ((!_pfd[j].revents & POLLIN))
				continue;
			
			_pfd[j].events = POLLIN;
			_pfd[j].revents = 0;

			err = read(zc_ctl[j]->fd, &ring, sizeof(ring));
			if (err <= 0) {
				fprintf(stderr, "Failed to read data from control file: %s [%d].\n", 
						strerror(errno), errno);
				return -2;
			}
			zcr = zcb[zc_ctl[j]->sniffer_id];
			num = err; 
			t_num += num;
			pos = ring.zc_used;
			for (i=0; i<num; ++i) {
				struct zc_data *z;
				char *ptr;
				struct zc_data *e;

				z = &zcr[pos++];

				if(pos == zc_ctl[j]->ring_num ) {
					pos = 0;
				}
				if (z->entry >= ZC_MAX_ENTRY_NUM )// || z->cpu >= nr_cpus)
					continue;

				e = &zc_ctl[z->cpu]->node_entries[z->entry];

#if 0 
				printf("dump %4d.%4d: ptr: %p, size: %u, off: %u: entry: %u, cpu: %d\n", 
					i, num, z->data.ptr, z->r_size, z->off, z->entry, z->cpu);
#endif
				ptr = e->data.ptr + z->off;

				//dump_skb("1", ptr, 64);
				ptr += 66; // (NET_MBUF_PAD_ALLOC+NET_IP_ALIGN);
				//dump_skb("2", ptr, 64);

				//ptr = e->data.ptr;
				//zc_analyze_write(out_fd, ptr, z->size);
				(*zc_analyze)(ptr, z->r_size, param);
			}
			err = write(zc_ctl[j]->fd, &ring, sizeof(ring));
			if (err < 0) {
				fprintf(stderr, "Failed to write data to control file: %s [%d].\n", 
						strerror(errno), errno);
				return -3;
			} 
			if(err!=num) {
				printf("!!! read %d but write %d\n", num, err);
			}
		}
		return t_num;
}

int zc_save_into_pool(struct zc_user_control **zc_ctl, 
				 unsigned int nr_cpus,
				 struct zc_pool *pool)
{
	int poll_ready, i, j, pos;
	int err;
	unsigned int num, t_num=0;
	struct zc_ring ring;
	struct zc_data *zcr;

	poll_ready = poll(_pfd, nr_cpus, 1000);
	if (poll_ready == 0){
		return 0;
	}
	if (poll_ready < 0)
		return -1;

	for (j=0; j<poll_ready; ++j) {
		if ((!_pfd[j].revents & POLLIN))
			continue;

		_pfd[j].events = POLLIN;
		_pfd[j].revents = 0;

		err = read(zc_ctl[j]->fd, &ring, sizeof(ring));
		if (err <= 0) {
			fprintf(stderr, "Failed to read data from control file: %s [%d].\n", 
					strerror(errno), errno);
			return -2;
		}
		zcr = zcb[zc_ctl[j]->sniffer_id];
		num = err; 
		t_num += num;
		pos = ring.zc_used;
		for (i=0; i<num; ++i) {
			struct zc_data *z;
			char *ptr;
			struct zc_data *e;

			z = &zcr[pos++];

			if(pos == zc_ctl[j]->ring_num ) {
				pos = 0;
			}
			if (z->entry >= ZC_MAX_ENTRY_NUM )// || z->cpu >= nr_cpus)
				continue;

			e = &zc_ctl[z->cpu]->node_entries[z->entry];

#if 0 
			printf("dump %4d.%4d: ptr: %p, size: %u, off: %u: entry: %u, cpu: %d\n", 
				i, num, z->data.ptr, z->r_size, z->off, z->entry, z->cpu);
#endif
			ptr = e->data.ptr + z->off;

			//dump_skb("1", ptr, 64);
			ptr += 66; // (NET_MBUF_PAD_ALLOC+NET_IP_ALIGN);
			//dump_skb("2", ptr, 64);
			pool->_pool[i] = ptr;
			pool->_len[i] = z->r_size;
			pool->num++;
			pool->ring_rec[j].zc_pos = ring.zc_pos;
			pool->ring_rec[j].zc_used = ring.zc_used;
		}
	}
	return pool->num; //t_num;
}

int zc_release_pool(struct zc_user_control **zc_ctl, 
				 unsigned int nr_cpus,
				 struct zc_pool *pool)
{
	int err;
	int i;
	
	for(i=0; i<nr_cpus; i++) {
		if(*(u_int32_t*)&pool->ring_rec[i]) {
			err = write(zc_ctl[i]->fd, &pool->ring_rec[i], sizeof(struct zc_ring));
			if (err < 0) {
				fprintf(stderr, "Failed to write data to control file: %s [%d].\n", 
						strerror(errno), errno);
				continue;
			} 
		}
	}
	return 0;
}

void * zc_alloc_buffer(struct zc_user_control *ctl,
                       struct zc_alloc_ctl *alloc_ctl)
{
    struct zc_data *z, *e;
    int err;
    void *ptr;
    
    err = ioctl(ctl->fd, ZC_ALLOC, alloc_ctl);
    if (err) {
        fprintf(stderr, "Failed to alloc from kernel: %s [%d].\n", strerror(errno), errno);
        return NULL;
    }
    z = &alloc_ctl->zc;
    //printf("cpu: %d, ptr: %p, size: %u [%u], reserve: %u, off: %u: entry: %u.\n", 
    //	z->cpu, z->data.ptr, z->size, size, res_len, z->off, z->entry);
    if (z->entry >= ZC_MAX_ENTRY_NUM){
        //|| z->cpu >= nr_cpus) {
        fprintf(stderr, "Wrong entry, exiting.\n");
        return NULL;
    }
    /*if (zc_prepare(ctl, z->entry))
        break;
    */
    e = &ctl->node_entries[z->entry];
    ptr = e->data.ptr + z->off;
    //printf("alloc: e->data.ptr %p z->data.ptr %p z->off %d\n", 
    //	   e->data.ptr, z->data.ptr, z->off);
    return ptr;
}

int zc_commit_buffer(struct zc_user_control *ctl, struct zc_alloc_ctl *alloc_ctl)
{
    int err;
	
    err = ioctl(ctl->fd, ZC_COMMIT, alloc_ctl);
    if (err) {
        fprintf(stderr, "Failed to commit buffer: %s [%d].\n", strerror(errno), errno);
        return err;
    }
    return 0;
}

void zc_ctl_shutdown(struct zc_user_control *zc)
{
    close(zc->fd);
    if(_pfd){
        free(_pfd);
        _pfd = NULL;
    }
}


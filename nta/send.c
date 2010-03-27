/*
 * 	send.c
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
#define _GNU_SOURCE
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
#include <utmpx.h>

#include <netinet/ip.h>

#include <linux/types.h>

#include "control.h"

struct zc_control *zc_ctl[NTA_NR_CPUS];

static inline __u32 num2ip(__u8 a0, __u8 a1, __u8 a2, __u8 a3)
{
	__u32 ret = 0;

	ret |= a0;
	ret <<= 8;
	ret |= a1;
	ret <<= 8;
	ret |= a2;
	ret <<= 8;
	ret |= a3;

	return ret;
}

static void zsend_usage(char *p)
{
	fprintf(stderr, "Usage: %s -f ctl_file -o output_file -c nr_cpus -s size -r reserved_size -h\n", p);
}

int main(int argc, char *argv[])
{
	int ch, err, size, res_len;
	unsigned int nr_cpus;
	char *ctl_file;
	struct zc_data *e;
	struct zc_control *ctl;
	void *ptr;
	struct iphdr *iph;
	int i;
	//int test=6000;
	int prev_cpu, cpu;

	ctl_file = NULL;
	size = 1400;
	res_len = 256;
	nr_cpus = 2;


	while ((ch = getopt(argc, argv, "r:c:s:f:h")) != -1) {
		switch (ch) {
			case 'c':
				nr_cpus = atoi(optarg);
				break;
			case 'r':
				res_len = atoi(optarg);
				break;
			case 's':
				size = atoi(optarg);
				break;
			case 'f':
				ctl_file = optarg;
				break;
			case 'h':
			default:
				zsend_usage(argv[0]);
				return 0;
		}
	}


	for(i=0; i<nr_cpus; i++){
		zc_ctl[i] = zc_ctl_init(i, ctl_file);
		if (!zc_ctl[i])
			return -1;
	}

	if (!zc_ctl)
		return -1;

	prev_cpu = cpu = sched_getcpu();
	printf("current process running on CPU %d\n", cpu);
	while (1) {
		struct zc_alloc_ctl alloc_ctl;
		
		prev_cpu = sched_getcpu();
		
		/* set per alloc condition */
		memset(&alloc_ctl, 0, sizeof(struct zc_alloc_ctl));
		alloc_ctl.zc.r_size = size; 
		alloc_ctl.proto = 0;

		/* allocate buffer from kernel */
		ptr = zc_alloc_buffer(zc_ctl[prev_cpu], &alloc_ctl);
		if(!ptr) {
			break;
		}
		/* fuck the buffer (ptr) */
		memset(ptr, 0xcd, size);
	
		iph = ptr + res_len;
		iph->saddr = htonl(num2ip(192, 168, 4, 78));
		//iph->daddr = htonl(num2ip(192, 168, 0, 48));
		iph->daddr = htonl(num2ip(127, 0, 0, 1));
		iph->protocol = IPPROTO_UDP;
		iph->tot_len = htons(size-res_len);
	
		cpu = sched_getcpu();
		if(cpu != prev_cpu) {
			printf("CPU changed!!!\n");
		}
		
		/* commit the buffer to CPU */
		alloc_ctl.res_len = res_len;
		alloc_ctl.zc.netdev_index = 0;
		zc_commit_buffer(zc_ctl[prev_cpu], &alloc_ctl);
	}
	return 0;
}

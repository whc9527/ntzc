/*
 * 	sniff.c
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
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/types.h>
#include <linux/if.h>


#include "control.h"

#define NR_CPUS			2
struct zc_control *zc_ctl[NR_CPUS];

unsigned long g_count, g_num_read, g_num_write;
static int terminated;

static void zc_usage(char *p)
{
	fprintf(stderr, "Usage: %s -f sniffer_file -c nr_cpus -i ifname\n", p);
}


#define NIPE(eth) \
	(eth)->ether_shost[0], \
	(eth)->ether_shost[1], \
	(eth)->ether_shost[2], \
	(eth)->ether_shost[3], \
	(eth)->ether_shost[4], \
	(eth)->ether_shost[5], \
	(eth)->ether_dhost[0], \
	(eth)->ether_dhost[1], \
	(eth)->ether_dhost[2], \
	(eth)->ether_dhost[3], \
	(eth)->ether_dhost[4], \
	(eth)->ether_dhost[5]

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static void zc_analyze(void *ptr, int length, char *nouse)
{
	struct ether_header *eth;
	struct iphdr *iph;
	struct tcphdr *th;
	unsigned char *p = ptr;
	__u16 sport, dport;
	struct test_sig{
		unsigned long count;
		unsigned long timestamp;
	}*sig;

	ptr += 64;
	eth = ptr+2;
	sig = (struct test_sig*)ptr;

	if(terminated) {
		return;
	}

#if 1
	printf("length %d %u.%u.%u.%u -> %u.%u.%u.%u, proto l3 %x, l4 %u",
			length, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(eth->ether_type), iph->protocol);
	if (eth->ether_type == ntohs(ETHERTYPE_IP)){
		iph = (struct iphdr *)(eth + 1);
		sport = ((__u16 *)(((void *)iph) + (iph->ihl<<2)))[0];
		dport = ((__u16 *)(((void *)iph) + (iph->ihl<<2)))[1];

		if(iph->protocol == IPPROTO_TCP) {
			printf(" port %u -> %u", ntohs(sport), ntohs(dport));
			th = (struct tcphdr *)(((void *)iph) + (iph->ihl<<2));
			printf("seq: %u, ack: %u, ", ntohl(th->seq), ntohl(th->ack_seq));
		}
		if(iph->protocol == IPPROTO_UDP) {
			printf(" port %u -> %u", ntohs(sport), ntohs(dport));
		}
	}
	printf("\n");
#endif
	return;
}


void sig_int(int sig)
{
	terminated = 1;
}

int main(int argc, char *argv[])
{
	int ch;
	unsigned int i, nr_cpus;
	char *ctl_file, *ifname;
	int dev_index;
	struct pollfd *pfd;
	struct zc_control *ctl;

	ctl_file = ifname = NULL;
	nr_cpus = NR_CPUS;
	g_count = 0;
	while ((ch = getopt(argc, argv, "f:i:c:h")) != -1) {
		switch (ch) {
			case 'c':
				nr_cpus = atoi(optarg);
				break;
			case 'i':
				ifname = optarg;
				break;
			case 'f':
				ctl_file = optarg;
				break;
			case 'h':
			default:
				zc_usage(argv[0]);
				return 0;
		}
	}

	if (nr_cpus > 1024) {
		fprintf(stderr, "Wrong number of CPUs %d.\n", nr_cpus);
		zc_usage(argv[0]);
		return -1;
	}

	if(!ifname){
		fprintf(stderr, "You must specify NIC interface name.\n");
		zc_usage(argv[0]);
		return -1;
	}
	
	{
		struct sigaction sa = { { 0 } };

		sa.sa_handler = sig_int;
		sigaction(SIGINT, &sa, NULL);

		sa.sa_handler = sig_int;
		sigaction(SIGTERM, &sa, NULL);
	}
		
	/* initialize zc control */		
	for(i=0; i<nr_cpus; i++){
		zc_ctl[i] = zc_ctl_init(i, ctl_file);
		if (!zc_ctl[i])
			return -1;
	}
	
	/* setup polling */
	zc_ctl_prepare_polling(zc_ctl, nr_cpus);

	/* get available interface id by known name */
	dev_index = zc_ctl_get_devid(zc_ctl[0], ifname);
	if(dev_index < 0) {
		fprintf(stderr, "Unable to get NIC interface name %s.\n", ifname);
		return -EINVAL;
	}

	/* bind interface to cpu */
	for (i=0; i<nr_cpus; ++i) {
		zc_ctl_set_sniff(zc_ctl[i], dev_index, ZC_SNIFF_RX);
	}
	
	/* no recv packet by the loop*/
	while (!terminated) {
		int i;
		i = zc_recv_loop(zc_ctl, nr_cpus, NULL, zc_analyze);
		if(i<0) {
			printf("Error in the zc recv loop %d\n", i);
			break;
		}
		g_num_read += i;
	}

	for(i=0; i<nr_cpus; i++) {
		zc_ctl_set_sniff(zc_ctl[i], dev_index, 0);
	}
	
	for(i=0; i<nr_cpus; i++) {
		zc_ctl_shutdown(zc_ctl[i]);
	}

	printf("current count: g_count %lu g_num_write %lu g_num_read %lu\n",
		   g_count, g_num_write, g_num_read);
	return 0;
}

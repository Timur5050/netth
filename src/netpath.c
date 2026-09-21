// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "netpath.skel.h"
#include "../common.h"

static volatile sig_atomic_t stop;
static void on_sigint(int sig)
{
	(void)sig;
	stop = 1;
}

static const char *stage_name(int s)
{
	switch (s) {
	case STAGE_SOCKET: return "udp_sendmsg        [socket]";
	case STAGE_IP:      return "ip_send_skb        [ip]";
	case STAGE_ROUTE:   return "ip_finish_output2  [route]";
	case STAGE_DEV:     return "__dev_queue_xmit   [device]";
	case STAGE_DRIVER:  return "e1000_xmit_frame   [driver]";
	default: return "?";
	}
}

static void print_available_interfaces(void)
{
	struct ifaddrs *ifaddr, *ifa;

	printf("=== avail network devices ===\n");
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return;
	}
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
			continue;
		char ip[INET_ADDRSTRLEN];
		struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
		inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
		unsigned int idx = if_nametoindex(ifa->ifa_name);
		printf("  [%u] %-12s %s\n", idx, ifa->ifa_name, ip);
	}
	freeifaddrs(ifaddr);
	printf("===============================================\n\n");
}

#define MAX_TRACK 4096
struct track {
	unsigned long long skb;
	unsigned long long ts[STAGE_MAX];
	struct event last;
	int used;
};
static struct track table[MAX_TRACK];

static struct track *find_or_alloc(unsigned long long skb)
{
	int free_slot = -1;

	for (int i = 0; i < MAX_TRACK; i++) {
		if (table[i].used && table[i].skb == skb)
			return &table[i];
		if (!table[i].used && free_slot < 0)
			free_slot = i;
	}
	if (free_slot < 0)
		free_slot = 0;

	memset(&table[free_slot], 0, sizeof(table[free_slot]));
	table[free_slot].used = 1;
	table[free_slot].skb = skb;
	return &table[free_slot];
}

static void print_final(struct track *t)
{
	struct event *e = &t->last;
	char sip[INET_ADDRSTRLEN] = "-", dip[INET_ADDRSTRLEN] = "-";
	struct in_addr a;

	if (e->saddr) {
		a.s_addr = e->saddr;
		inet_ntop(AF_INET, &a, sip, sizeof(sip));
	}
	if (e->daddr) {
		a.s_addr = e->daddr;
		inet_ntop(AF_INET, &a, dip, sizeof(dip));
	}

	printf("\n=== packet skb=0x%llx  pid=%u (%s) ===\n",
	       (unsigned long long)t->skb, e->pid, e->comm);
	printf("  %s:%u -> %s:%u   len=%u байт\n", sip, e->sport, dip, e->dport, e->len);
	if (e->ifname[0])
		printf("  output device: %s (ifindex %u)\n", e->ifname, e->ifindex);
	printf("  src MAC: %02x:%02x:%02x:%02x:%02x:%02x   dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       e->src_mac[0], e->src_mac[1], e->src_mac[2], e->src_mac[3], e->src_mac[4], e->src_mac[5],
	       e->dst_mac[0], e->dst_mac[1], e->dst_mac[2], e->dst_mac[3], e->dst_mac[4], e->dst_mac[5]);

	printf("  --- time---\n");
	unsigned long long prev = 0, first = 0;
	for (int s = 0; s < STAGE_MAX; s++) {
		if (!t->ts[s])
			continue;
		if (!first) {
			first = t->ts[s];
			prev = t->ts[s];
		}
		double from_start = (t->ts[s] - first) / 1000.0;
		double from_prev = (t->ts[s] - prev) / 1000.0;
		printf("    %-28s +%8.3f us   (Δ %6.3f us)\n",
		       stage_name(s), from_start, from_prev);
		prev = t->ts[s];
	}
	printf("=========================================\n");
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	(void)len;
	struct event *e = data;

	if (e->stage == STAGE_SOCKET) {
		printf("[socket] pid=%u comm=%s len=%u ->  UDP send\n",
		       e->pid, e->comm, e->len);
		return 0;
	}

	struct track *t = find_or_alloc(e->skb);
	t->ts[e->stage] = e->ts_ns;
	t->last.pid = e->pid;
	strcpy(t->last.comm, e->comm);
	if (e->saddr) t->last.saddr = e->saddr;
	if (e->daddr) t->last.daddr = e->daddr;
	if (e->sport) t->last.sport = e->sport;
	if (e->dport) t->last.dport = e->dport;
	if (e->len)   t->last.len = e->len;
	if (e->ifindex) {
		t->last.ifindex = e->ifindex;
		strcpy(t->last.ifname, e->ifname);
	}
	if (e->src_mac[0] || e->src_mac[1] || e->src_mac[2]) {
		memcpy(t->last.src_mac, e->src_mac, 6);
		memcpy(t->last.dst_mac, e->dst_mac, 6);
	}

	if (e->stage == STAGE_DRIVER) {
		print_final(t);
		t->used = 0;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct netpath_bpf *skel;
	struct ring_buffer *rb = NULL;
	unsigned short dport = 0;
	int err;

	if (argc > 1)
		dport = (unsigned short)atoi(argv[1]);

	print_available_interfaces();

	skel = netpath_bpf__open();
	if (!skel) {
		fprintf(stderr, "noway to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->target_dport = dport;

	err = netpath_bpf__load(skel);
	if (err) {
		fprintf(stderr, "load bpf program: %d\n", err);
		goto cleanup;
	}

	err = netpath_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "atach to to kprobe: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "cannot create ring buffer\n");
		err = 1;
		goto cleanup;
	}

	signal(SIGINT, on_sigint);
	printf(" UDP TX%s\n\n",
	       dport ? " (dst port)" : "");

	while (!stop) {
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, " poll: %d\n", err);
			break;
		}
	}

	err = 0;
cleanup:
	ring_buffer__free(rb);
	netpath_bpf__destroy(skel);
	return err;
}

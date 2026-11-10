// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

volatile const unsigned short target_dport = 0;

static __always_inline struct event *reserve_event(void)
{
	return bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
}

static __always_inline void fill_common(struct event *e, struct sk_buff *skb, unsigned char stage)
{
	__builtin_memset(e, 0, sizeof(*e));
	e->skb = (unsigned long long)skb;
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->stage = stage;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline bool check_port(struct sock *sk)
{
	if (!target_dport)
		return true;
	if (!sk)
		return false;

	unsigned short dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	return bpf_ntohs(dport) == target_dport;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	if (!check_port(sk))
		return 0;

	struct event *e = reserve_event();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->stage = STAGE_SOCKET;
	e->len = (unsigned int)len;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/ip_send_skb")
int BPF_KPROBE(trace_ip_send_skb, struct net *net, struct sk_buff *skb)
{
	struct sock *sk = BPF_CORE_READ(skb, sk);
	if (!check_port(sk))
		return 0;

	struct event *e = reserve_event();
	if (!e) return 0;
	fill_common(e, skb, STAGE_IP);

	void *head = BPF_CORE_READ(skb, head);
	unsigned short net_off = BPF_CORE_READ(skb, network_header);
	struct iphdr iph = {};
	bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);

	e->saddr = iph.saddr;
	e->daddr = iph.daddr;
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	e->sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/ip_finish_output2")
int BPF_KPROBE(trace_ip_finish_output2, struct net *net, struct sock *sk, struct sk_buff *skb)
{
	if (!check_port(sk))
		return 0;

	struct event *e = reserve_event();
	if (!e) return 0;
	fill_common(e, skb, STAGE_ROUTE);

	struct net_device *dev = BPF_CORE_READ(skb, dev);
	if (dev) {
		e->ifindex = BPF_CORE_READ(dev, ifindex);
		bpf_probe_read_kernel_str(e->ifname, sizeof(e->ifname), dev->name);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(trace_dev_queue_xmit, struct sk_buff *skb)
{
	struct sock *sk = BPF_CORE_READ(skb, sk);
	if (!check_port(sk))
		return 0;

	struct event *e = reserve_event();
	if (!e) return 0;
	fill_common(e, skb, STAGE_DEV);

	struct net_device *dev = BPF_CORE_READ(skb, dev);
	if (dev) {
		e->ifindex = BPF_CORE_READ(dev, ifindex);
		bpf_probe_read_kernel_str(e->ifname, sizeof(e->ifname), dev->name);
		bpf_probe_read_kernel(e->src_mac, 6, BPF_CORE_READ(dev, dev_addr));
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/e1000_xmit_frame")
int BPF_KPROBE(trace_e1000_xmit_frame, struct sk_buff *skb)
{
	struct sock *sk = BPF_CORE_READ(skb, sk);
	if (!check_port(sk))
		return 0;

	struct event *e = reserve_event();
	if (!e) return 0;
	fill_common(e, skb, STAGE_DRIVER);
	e->len = BPF_CORE_READ(skb, len);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

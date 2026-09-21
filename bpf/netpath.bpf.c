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


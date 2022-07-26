// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Subao Network Inc.*/
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} outer_map SEC(".maps");

SEC("sk_reuseport")
int select_by_skb_data(struct sk_reuseport_md *reuse_md)
{
	void *reuseport_array;
	__u32 index_zero = 0, inner_key = 0;
	__u16 sport, dport;
	void *data = reuse_md->data;
	void *data_end = reuse_md->data_end;
	struct udphdr *uh = reuse_md->data;
	struct udphdr uhd;
	int err;

	if (reuse_md->eth_protocol != bpf_htons(ETH_P_IP)) {
		bpf_printk("drop non-ip packet");
		return SK_DROP;
	}

	if (reuse_md->ip_protocol != IPPROTO_UDP) {
		bpf_printk("drop non-udp packet");
		return SK_DROP;
	}

	if ((void *)(uh + 1) > data_end) {
		bpf_printk("drop invalid udp packet");
		return SK_DROP;
	}

	err = bpf_skb_load_bytes_relative(reuse_md, sizeof(struct iphdr), &uhd,
					  sizeof(struct udphdr),
					  BPF_HDR_START_NET);
	if (err) {
		bpf_printk("drop packet as can not load udp header bytes");
		return SK_DROP;
	}

	sport = bpf_ntohs(uhd.source);
	dport = bpf_ntohs(uhd.dest);
	bpf_printk("received packet with sport %u dport %u", sport, dport);

	reuseport_array = bpf_map_lookup_elem(&outer_map, &index_zero);
	if (!reuseport_array) {
		bpf_printk("drop packet as no reuseport_array found");
		return SK_DROP;
	}

	inner_key = sport % 2;
	err = bpf_sk_select_reuseport(reuse_md, reuseport_array, &inner_key, 0);
	if (err) {
		bpf_printk("drop packet as no key %d in reuseport, err %d",
			   inner_key, err);
		return SK_DROP;
	}

	return SK_PASS;
}
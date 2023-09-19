//go:build ignore

/* Copyright Authors of Cilium */
//#include "uapi/linux/bpf.h"
//#include "bpf/bpf_helpers.h"
//#include <linux/types.h>
//#include <stdbool.h>
//#include <errno.h>
#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual BSD/GPL";

#define MAX_MAP_ENTRIES 16

#define SYS_REJECT 0
#define SYS_PROCEED 1
#define DEFAULT_MAX_EBPF_MAP_ENTRIES 65536
#define IPPROTO_TCP 6

struct V4_key {
  __be32 address;     /* Service virtual IPv4 address  4*/
  __be16 dport;       /* L4 port filter, if unset, all ports apply   */
  __u16 backend_slot; /* Backend iterator, 0 indicates the svc frontend  2*/
};

struct lb4_service {
  union {
    __u32 backend_id;       /* Backend ID in lb4_backends */
    __u32 affinity_timeout; /* In seconds, only for svc frontend */
    __u32 l7_lb_proxy_port; /* In host byte order, only when flags2 &&
                               SVC_FLAG_L7LOADBALANCER */
  };
  /* For the service frontend, count denotes number of service backend
   * slots (otherwise zero).
   */
  __u16 count;
  __u16 rev_nat_index; /* Reverse NAT ID in lb4_reverse_nat */
  __u8 flags;
  __u8 flags2;
  __u8 pad[2];
};

struct lb4_backend {
  __be32 address; /* Service endpoint IPv4 address */
  __be16 port;    /* L4 port filter */
  __u8 flags;
};


struct {
  __uint(type, BPF_MAP_TYPE_HASH); 
  __type(key, struct V4_key);
  __type(value, struct lb4_service); 
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENTRIES);
} v4_svc_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH); 
  __type(key, __u32);
  __type(value, struct lb4_backend); 
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENTRIES);
} v4_backend_map SEC(".maps");


/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
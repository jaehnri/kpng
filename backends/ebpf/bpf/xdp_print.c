//go:build ignore

/* Copyright Authors of Cilium */
//#include "uapi/linux/bpf.h"
//#include "bpf/bpf_helpers.h"
//#include <linux/types.h>
//#include <stdbool.h>
//#include <errno.h>
#include "bpf_endian.h"
#include "common.h"
#include <errno.h>

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

// Uses v4_svc_map to find a Kubernetes service
/*static __always_inline struct lb4_service *
lb4_lookup_service(struct V4_key *key) {
  struct lb4_service *svc;

  svc = bpf_map_lookup_elem(&v4_svc_map, key);
  if (svc) {
    return svc;
  }

  return NULL;
}*/

// Uses v4_svc_map to find a backend_slot given a key with backend_slot 
/*static __always_inline struct lb4_service *
__lb4_lookup_backend_slot(struct V4_key *key) {
  return bpf_map_lookup_elem(&v4_svc_map, key);
}

// Performs a query on v4_backend_map to find an Endpoint given the backend_id
static __always_inline struct lb4_backend *
__lb4_lookup_backend(__u32 backend_id) {
  return bpf_map_lookup_elem(&v4_backend_map, &backend_id);
}*/

/* Generates a random u32 number */
/*static __always_inline __u64 sock_select_slot(struct iphdr *iph) {
  return iph->protocol == IPPROTO_TCP ? bpf_get_prandom_u32() : 0;
}*/

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	//__be32 dest_ip;
	//__be16 dest_port;

  // Parse the raw packge the get the protocol headers
 	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_PASS;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return XDP_PASS;
	}

	// Then parse the IP header.
	struct iphdr *iph = data + sizeof(*eth);
	if (data + sizeof(struct ethhdr) +  sizeof(struct iphdr) > data_end) {
		return XDP_PASS;
	}

	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	// Then parse the TCP header
	struct tcphdr *tcp = (struct tcphdr *)(iph + 1);
	if ((void *)(tcp + 1) > data_end)
		return XDP_PASS;

	// Save the destination IP address and TCP port
	//dest_ip = (__be32)(iph->daddr);
	//dest_port = (__be16)(tcp->dest);

  //bpf_trace_printk("Destination address: %x and port %x\n", dest_ip, dest_port);

  // Start backend lookup
	/*struct V4_key key = {
		.address = dest_ip,
		.dport = dest_port,
		.backend_slot = 0
	};

  struct lb4_service *svc;*/
  //struct lb4_service *backend_slot;
  //struct lb4_backend *backend = NULL;

	//__u32 backend_id = 0;

	// The first lookup is meant to see if the "Service frontend" exists and check how many 
  // backends, i.e, Endpoints, it has
  /*svc = lb4_lookup_service(&key);
  if (!svc) {
  	return -ENXIO;
  }*/
  
  // Logs are in /tracing/trace_pipe inside the kpng-ebpf-tools container
  //const char debug_str[] = "Entering the kpng ebpf backend, caught a\
  //packet destined for my VIP, the address is: %x port is: %x and selected backend id is: %x\n";
  
  //bpf_trace_printk(debug_str, sizeof(debug_str),  key.address, key.dport, svc->backend_id);

  /*if (backend_id == 0) {
    // Do load-balancing by sorting a backend. Then, lookups the same v4_svc_map
    // with the key.backend_slot filled to get the backend_id relative to the sorted backend
    key.backend_slot = (sock_select_slot(iph) % svc->count) + 1;
    backend_slot = __lb4_lookup_backend_slot(&key);
    if (!backend_slot) {
      return -ENOENT;
    }

    // The backend_id is used to fetch the final Endpoint
    backend_id = backend_slot->backend_id;
    backend = __lb4_lookup_backend(backend_id);
  }

  if (!backend) {
    return -ENOENT;
  }*/

  // Maybe add that in the future
  /*if (sock4_skip_xlate_if_same_netns(ctx, backend)) {
    return -ENXIO;
  }*/

  /*iph->daddr = dest_ip;
  tcp->dest = dest_port;*/

	return XDP_PASS;
}
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#include "uapi/linux/bpf.h"
#include "bpf/bpf_helpers.h"
#include <linux/types.h>
#include <stdbool.h>
#include <errno.h>
#include "bpf_endian.h"
#include "common.h"
//#include "vmlinux.h"

#define SYS_REJECT 0
#define SYS_PROCEED 1
#define DEFAULT_MAX_EBPF_MAP_ENTRIES 65536
#define MAX_MAP_ENTRIES 16

#define DEBUG_ENABLED true
#define DEBUG_BPF_PRINTK(...) if(DEBUG_ENABLED) {bpf_printk(__VA_ARGS__);}
#define ETH_P_IP	0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IP_CT_NEW 2



char __license[] SEC("license") = "Dual BSD/GPL";

struct V4_key {
__be32 address; /* Service virtual IPv4 address 4*/
__be16 dport; /* L4 port filter, if unset, all ports apply */
__u16 backend_slot; /* Backend iterator, 0 indicates the svc frontend 2*/
};

struct lb4_service {
union {
__u32 backend_id; /* Backend ID in lb4_backends */
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
__be16 port; /* L4 port filter */
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

static __always_inline struct lb4_service *
lb4_lookup_service(struct V4_key *key) {
struct lb4_service *svc;

svc = bpf_map_lookup_elem(&v4_svc_map, key);
if (svc) {
return svc;
}

return NULL;
}

/* Hack due to missing narrow ctx access. */
static __always_inline __be16 ctx_dst_port(const struct bpf_sock_addr *ctx) {
volatile __u32 dport = ctx->user_port;

return (__be16)dport;
}

static __always_inline __u64 sock_select_slot(struct bpf_sock_addr *ctx) {
return ctx->protocol == IPPROTO_TCP ? bpf_get_prandom_u32() : 0;
}

static __always_inline struct lb4_backend *
__lb4_lookup_backend(__u32 backend_id) {
return bpf_map_lookup_elem(&v4_backend_map, &backend_id);
}

static __always_inline struct lb4_service *
__lb4_lookup_backend_slot(struct V4_key *key) {
return bpf_map_lookup_elem(&v4_svc_map, key);
}

/* Service translation logic for a local-redirect service can cause packets to
* be looped back to a service node-local backend after translation. This can
* happen when the node-local backend itself tries to connect to the service
* frontend for which it acts as a backend. There are cases where this can break
* traffic flow if the backend needs to forward the redirected traffic to the
* actual service frontend. Hence, allow service translation for pod traffic
* getting redirected to backend (across network namespaces), but skip service
* translation for backend to itself or another service backend within the same
* namespace. Currently only v4 and v4-in-v6, but no plain v6 is supported.
*
* For example, in EKS cluster, a local-redirect service exists with the AWS
* metadata IP, port as the frontend <169.254.169.254, 80> and kiam proxy as a
* backend Pod. When traffic destined to the frontend originates from the kiam
* Pod in namespace ns1 (host ns when the kiam proxy Pod is deployed in
* hostNetwork mode or regular Pod ns) and the Pod is selected as a backend, the
* traffic would get looped back to the proxy Pod. Identify such cases by doing
* a socket lookup for the backend <ip, port> in its namespace, ns1, and skip
* service translation.
*/
static __always_inline bool
sock4_skip_xlate_if_same_netns(struct bpf_sock_addr *ctx,
const struct lb4_backend *backend) {
#ifdef BPF_HAVE_SOCKET_LOOKUP
struct bpf_sock_tuple tuple = {
.ipv4.daddr = backend->address,
.ipv4.dport = backend->port,
};
struct bpf_sock *sk = NULL;

switch (ctx->protocol) {
case IPPROTO_TCP:
sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
break;
case IPPROTO_UDP:
sk = sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
break;
}

if (sk) {
sk_release(sk);
return true;
}
#endif /* BPF_HAVE_SOCKET_LOOKUP */
return false;
}

static __always_inline void ctx_set_port(struct bpf_sock_addr *ctx,
__be16 dport) {
ctx->user_port = (__u32)dport;
}

static __always_inline int __sock4_fwd(struct bpf_sock_addr *ctx) {
struct V4_key key = {
.address = ctx->user_ip4,
.dport = ctx_dst_port(ctx),
.backend_slot = 0,
};

struct lb4_service *svc;
struct lb4_service *backend_slot;
struct lb4_backend *backend = NULL;

__u32 backend_id = 0;

svc = lb4_lookup_service(&key);
if (!svc) {
return -ENXIO;
}

// Logs are in /sys/kernel/debug/tracing/trace_pipe

const char debug_str[] = "Entering the kpng ebpf backend, caught a\
packet destined for my VIP, the address is: %x port is: %x and selected backend id is: %x\n";

bpf_trace_printk(debug_str, sizeof(debug_str), key.address, key.dport, svc->backend_id);

if (backend_id == 0) {
key.backend_slot = (sock_select_slot(ctx) % svc->count) + 1;
backend_slot = __lb4_lookup_backend_slot(&key);
if (!backend_slot) {
return -ENOENT;
}

backend_id = backend_slot->backend_id;
backend = __lb4_lookup_backend(backend_id);
}

if (!backend) {
return -ENOENT;
}

if (sock4_skip_xlate_if_same_netns(ctx, backend)) {
return -ENXIO;
}

ctx->user_ip4 = backend->address;
ctx_set_port(ctx, backend->port);

return 0;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx) {

__sock4_fwd(ctx);
return SYS_PROCEED;
}

/*               NodePort Service                 */

struct nodeportV4_key {
    __be16 nodeport;
};

struct nodeportV4_backend {
    __be32 address;
    __be16 port;
};

struct {
__uint(type, BPF_MAP_TYPE_HASH);
__type(key, struct nodeportV4_key);
__type(value, struct nodeportV4_backend);
__uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENTRIES);
} v4_nodeport_map SEC(".maps");

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Check Ethernet header
    struct ethhdr *eth = data;
    if(data + sizeof(*eth) > data_end) 
        return XDP_PASS;
    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Initialize ct data structures
    struct bpf_sock_tuple bpf_tuple = {};
    struct bpf_ct_opts opts_def = {
        .netns_id = -1,
    };
    struct nf_conn *ct;

    // Check IP header
    struct iphdr *iph = data + sizeof(*eth);
    if((void *)(iph + 1) > data_end) 
        return XDP_PASS;


    // Check TCP/UDP headers
    opts_def.l4proto = iph->protocol;
    bpf_tuple.ipv4.saddr = iph->saddr;
    bpf_tuple.ipv4.daddr = iph->daddr;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if((void *)(tcph + 1) > data_end)
            return XDP_PASS;

        bpf_tuple.ipv4.sport = tcph->source;
        bpf_tuple.ipv4.dport = tcph->dest;

        __be32 aux = 67113644;
        __be16 aux2 = 6265;
        if (bpf_tuple.ipv4.daddr == aux && bpf_tuple.ipv4.dport == aux2) {
            DEBUG_BPF_PRINTK("Packet daddr: %u dport: %u", iph->daddr, tcph->dest);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if((void *)(udph + 1) > data_end)
            return XDP_PASS;

        bpf_tuple.ipv4.sport = udph->source;
        bpf_tuple.ipv4.dport = udph->dest;
    } else
        return XDP_PASS;

    // Lookup for nodeport entry in bpfmap
    struct nodeportV4_key key = {
        .nodeport = bpf_ntohs(bpf_tuple.ipv4.dport)
    };
    struct nodeportV4_backend *lkup = (struct nodeportV4_backend *) bpf_map_lookup_elem(&v4_nodeport_map, &key);
    if (!lkup) {

        __be32 aux = 67113644;
        __be16 aux2 = 6265;
        //__be32 aux = 2886860804;
        //__be16 aux2 = 31000;
        if (bpf_tuple.ipv4.daddr == aux && bpf_tuple.ipv4.dport == aux2) {
            DEBUG_BPF_PRINTK("lkup result: NULL \n")
        }
        return XDP_PASS;
    }
    DEBUG_BPF_PRINTK("lkup result: daddr %u dport %u\n", lkup->address, lkup->port)

    // Check for Conntrack entry
    ct = bpf_xdp_ct_lookup(ctx, &bpf_tuple, 
        sizeof(bpf_tuple.ipv4), &opts_def, sizeof(opts_def));
    if(ct) {
        DEBUG_BPF_PRINTK("CT lookup (ct found) 0x%X\n", ct)
        DEBUG_BPF_PRINTK("Timeout %u  status 0x%X dport 0x%X \n",  
                    ct->timeout, ct->status, bpf_tuple.ipv4.dport)
        if (iph->protocol == IPPROTO_TCP) {
            DEBUG_BPF_PRINTK("TCP proto state %u flags  %u/ %u  last_dir  %u  \n",
            ct->proto.tcp.state,
            ct->proto.tcp.seen[0].flags, ct->proto.tcp.seen[1].flags,
            ct->proto.tcp.last_dir)
        }
        bpf_ct_release(ct);
    } else{
        // Create new CT entry
        DEBUG_BPF_PRINTK("No CT entry found. Creating new CT entry.\n");
        struct nf_conn *nct = bpf_xdp_ct_alloc(ctx,
            &bpf_tuple, sizeof(bpf_tuple.ipv4),
            &opts_def, sizeof(opts_def));
        if(!nct) {
            DEBUG_BPF_PRINTK("Couldnt alloc ct table\n");
            return XDP_PASS;
        }

        
        // Add DNAT info
        union nf_inet_addr addr = {};
        addr.ip = 33620234;
        //addr.ip = lkup->address;
        //addr.ip = bpf_get_prandom_u32();
        __u16 port = 80;//bpf_get_prandom_u32();  


        DEBUG_BPF_PRINTK("NCT information 1 before Dnat dAddr %u, sAddr: %u dPort %u sPort %u",
         nct->tuplehash[1].tuple.dst.u3.ip, nct->tuplehash[1].tuple.src.u3.ip,
         nct->tuplehash[1].tuple.dst.u.all, nct->tuplehash[1].tuple.src.u.all);
        
        int res = bpf_ct_set_nat_info(nct, &addr, port, NF_NAT_MANIP_DST);
        DEBUG_BPF_PRINTK("Return from NAT function %d", res);
        if (res == -EINVAL) {
            DEBUG_BPF_PRINTK("Error setting first nat"); 
        }
        //DEBUG_BPF_PRINTK("NCT information 0 after Dnat destination %u, source: %u ",
        // nct->tuplehash[0].tuple.dst.u3.ip, nct->tuplehash[0].tuple.src.u3.ip);
        DEBUG_BPF_PRINTK("NCT information 1 after Dnat dAddr %u, sAddr: %u dPort %u sPort %u",
         nct->tuplehash[1].tuple.dst.u3.ip, nct->tuplehash[1].tuple.src.u3.ip,
         nct->tuplehash[1].tuple.dst.u.all, nct->tuplehash[1].tuple.src.u.all);
        
        // Add SNAT info
        addr.ip = bpf_tuple.ipv4.daddr;
        res = bpf_ct_set_nat_info(nct, &addr, -1, NF_NAT_MANIP_SRC);
        if (res) {
            DEBUG_BPF_PRINTK("Error setting second nat");
        }


        //DEBUG_BPF_PRINTK("NCT information 0 after Snat destination %u, source: %u ", nct->tuplehash[0].tuple.dst.u3.ip, nct->tuplehash[0].tuple.src.u3.ip);
        DEBUG_BPF_PRINTK("NCT information 1 after Snat dAddr %u, sAddr: %u dPort %u sPort %u",
         nct->tuplehash[1].tuple.dst.u3.ip, nct->tuplehash[1].tuple.src.u3.ip,
         nct->tuplehash[1].tuple.dst.u.all, nct->tuplehash[1].tuple.src.u.all);

        // Add timeout and insert entry
        bpf_ct_set_timeout(nct, 30000);
        bpf_ct_set_status(nct, IP_CT_NEW);
        //1DEBUG_BPF_PRINTK("nf_conn: %+\b", );
        ct = bpf_ct_insert_entry(nct);
        if(ct) {
            DEBUG_BPF_PRINTK("Successfully add CT entry.\n");
            bpf_ct_release(ct);
        } else {
            DEBUG_BPF_PRINTK("Could not add CT entry.\n");
        }
    }

    return XDP_PASS;
}
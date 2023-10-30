// This is a compact version of `vmlinux.h` to be used in the examples using C code.

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#include "bpf_helpers.h"

/*enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC                = 0,
	BPF_MAP_TYPE_HASH                  = 1,
	BPF_MAP_TYPE_ARRAY                 = 2,
	BPF_MAP_TYPE_PROG_ARRAY            = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
	BPF_MAP_TYPE_PERCPU_HASH           = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
	BPF_MAP_TYPE_STACK_TRACE           = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
	BPF_MAP_TYPE_LRU_HASH              = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
	BPF_MAP_TYPE_LPM_TRIE              = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
	BPF_MAP_TYPE_DEVMAP                = 14,
	BPF_MAP_TYPE_SOCKMAP               = 15,
	BPF_MAP_TYPE_CPUMAP                = 16,
	BPF_MAP_TYPE_XSKMAP                = 17,
	BPF_MAP_TYPE_SOCKHASH              = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE                 = 22,
	BPF_MAP_TYPE_STACK                 = 23,
	BPF_MAP_TYPE_SK_STORAGE            = 24,
	BPF_MAP_TYPE_DEVMAP_HASH           = 25,
	BPF_MAP_TYPE_STRUCT_OPS            = 26,
	BPF_MAP_TYPE_RINGBUF               = 27,
	BPF_MAP_TYPE_INODE_STORAGE         = 28,
};*/

/*enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
};*/

/*struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};*/

typedef __u16 __sum16;

#define ETH_P_IP 0x0800

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1: 4;
	__u16 doff: 4;
	__u16 fin: 1;
	__u16 syn: 1;
	__u16 rst: 1;
	__u16 psh: 1;
	__u16 ack: 1;
	__u16 urg: 1;
	__u16 ece: 1;
	__u16 cwr: 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};


struct in_addr {
	__be32 s_addr;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

union nf_inet_addr {
	__u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

struct bpf_ct_opts {
        s32 netns_id;
        s32 error;
        u8 l4proto;
        u8 dir;
        u8 reserved[2];
};

/*****************************/


typedef u64 u_int64_t;
typedef u32 u_int32_t;
typedef u16 u_int16_t;
typedef u8 u_int8_t;


struct nf_ct_dccp {
	u_int8_t role[2];
	u_int8_t state;
	u_int8_t last_pkt;
	u_int8_t last_dir;
	u_int64_t handshake_seq;
};

enum sctp_conntrack {
	SCTP_CONNTRACK_NONE = 0,
	SCTP_CONNTRACK_CLOSED = 1,
	SCTP_CONNTRACK_COOKIE_WAIT = 2,
	SCTP_CONNTRACK_COOKIE_ECHOED = 3,
	SCTP_CONNTRACK_ESTABLISHED = 4,
	SCTP_CONNTRACK_SHUTDOWN_SENT = 5,
	SCTP_CONNTRACK_SHUTDOWN_RECD = 6,
	SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7,
	SCTP_CONNTRACK_HEARTBEAT_SENT = 8,
	SCTP_CONNTRACK_HEARTBEAT_ACKED = 9,
	SCTP_CONNTRACK_MAX = 10,
};

struct ip_ct_sctp {
	enum sctp_conntrack state;
	__be32 vtag[2];
};

struct ip_ct_tcp_state {
	u_int32_t td_end;
	u_int32_t td_maxend;
	u_int32_t td_maxwin;
	u_int32_t td_maxack;
	u_int8_t td_scale;
	u_int8_t flags;
};

struct ip_ct_tcp {
	struct ip_ct_tcp_state seen[2];
	u_int8_t state;
	u_int8_t last_dir;
	u_int8_t retrans;
	u_int8_t last_index;
	u_int32_t last_seq;
	u_int32_t last_ack;
	u_int32_t last_end;
	u_int16_t last_win;
	u_int8_t last_wscale;
	u_int8_t last_flags;
};

struct nf_ct_udp {
	long unsigned int stream_ts;
};

struct nf_ct_gre {
	unsigned int stream_timeout;
	unsigned int timeout;
};

typedef u32 u_int32_t;
union nf_conntrack_proto {
	struct nf_ct_dccp dccp;
	struct ip_ct_sctp sctp;
	struct ip_ct_tcp tcp;
	struct nf_ct_udp udp;
	struct nf_ct_gre gre;
	unsigned int tmpl_padto;
};
struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};
struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};


union nf_conntrack_man_proto {
	__be16 all;
	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 id;
	} icmp;
	struct {
		__be16 port;
	} dccp;
	struct {
		__be16 port;
	} sctp;
	struct {
		__be16 key;
	} gre;
};

typedef u16 u_int16_t;
struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	u_int16_t l3num;
};

typedef unsigned char __u8;
typedef __u8 u8;
typedef u8 u_int8_t;
struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	struct {
		union nf_inet_addr u3;
		union {
			__be16 all;
			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type;
				u_int8_t code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;
		u_int8_t protonum;
		u_int8_t dir;
	} dst;
};
struct nf_conntrack_tuple_hash {
	struct hlist_nulls_node hnnode;
	struct nf_conntrack_tuple tuple;
};
typedef struct {
	int counter;
} atomic_t;
struct nf_conntrack {
	atomic_t use;
};

typedef struct {
	struct net *net;
} possible_net_t;

struct qspinlock {
	union {
		atomic_t val;
		struct {
			u8 locked;
			u8 pending;
		};
		struct {
			u16 locked_pending;
			u16 tail;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;
struct raw_spinlock {
	arch_spinlock_t raw_lock;
};
struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};
typedef struct spinlock spinlock_t;

struct nf_conn {
	struct nf_conntrack ct_general;
	spinlock_t lock;
	u32 timeout;
	struct nf_conntrack_tuple_hash tuplehash[2];
	long unsigned int status;
	u16 cpu;
	possible_net_t ct_net;
	struct hlist_node nat_bysource;
	struct {	} __nfct_init_offset;
	struct nf_conn *master;
	u_int32_t secmark;
	struct nf_ct_ext *ext;
	union nf_conntrack_proto proto;
};

enum nf_nat_manip_type {
	NF_NAT_MANIP_SRC,
	NF_NAT_MANIP_DST
};

struct nf_conn *
bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx, struct bpf_sock_tuple *bpf_tuple, u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;

struct nf_conn *
bpf_xdp_ct_alloc(struct xdp_md *xdp_ctx, struct bpf_sock_tuple *bpf_tuple,
		 u32 tuple__sz, struct bpf_ct_opts *opts, u32 opts__sz) __ksym;

struct nf_conn *bpf_ct_insert_entry(struct nf_conn *nfct_i) __ksym;


void bpf_ct_set_timeout(struct nf_conn *nfct, u32 timeout) __ksym;

int bpf_ct_set_status(const struct nf_conn *nfct, u32 status) __ksym;

void bpf_ct_release(struct nf_conn *) __ksym;

int bpf_ct_set_nat_info(struct nf_conn *nfct,
                        union nf_inet_addr *addr, int port,
                        enum nf_nat_manip_type manip) __ksym;

/*enum {
	BPF_ANY     = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST   = 2,
	BPF_F_LOCK  = 4,
};*/

/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	/*
	 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
	 * unless syscall needs a complete, fully filled "struct pt_regs".
	 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	/*
	 * On syscall entry, this is syscall#. On CPU exception, this is error code.
	 * On hw interrupt, it's IRQ number:
	 */
	unsigned long orig_rax;
	/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	/* top of stack page */
};
#endif /* __TARGET_ARCH_x86 */
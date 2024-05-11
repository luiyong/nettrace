#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


#include "tcp_trace.h"
 
#define MAX_ENTRIES 64
#define AF_INET    2
#define AF_INET6   10
 
 char LICENSE[] SEC("license") = "Dual BSD/GPL";

 const volatile pid_t targ_tgid = 0;
 const volatile __u16 targ_lport = 0;

 struct tuple_key{
	u32 saddr;
	u32 daddr;
	u16 dport;
	u16 lport;
};

struct tuple_val{
	int mss;
	int size_goal;
	int gso;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tuple_key);
	__type(value, struct tuple_val);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

 
SEC("fexit/tcp_send_mss")
int BPF_PROG(tcp_send_mss, struct sock *sk, int *size_goal, int flags, int ret)
{
	struct tcp_sock *tp = (struct tcp_sock*)sk;
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	char comm[TASK_COMM_LEN];
	// 读取 size_goal 的值
	int size = 0;
	if(size_goal)
	{
		bpf_probe_read(&size, sizeof(size), (void *)size_goal);
	}

	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	int gso  = BPF_CORE_READ(tp, gso_segs);

    if (family != AF_INET) {
        return 0;
    }

	struct tuple_key key = {0};
	key.daddr = daddr;
	key.saddr = saddr;
	key.dport = dport;
	key.lport = lport;

	// /* if we recorded start of the process, calculate lifetime duration */
	// struct tuple_val *val = bpf_map_lookup_elem(&start, &key);
	// if(!val)
	// 	return 0;
	struct tuple_val val = {};
	val.size_goal = size;
	val.gso = gso;
	val.mss = ret;
	bpf_map_update_elem(&start, &key, &val, BPF_ANY);

	bpf_get_current_comm(&comm, sizeof(comm));
	
	if(lport == 8080)
	{
		bpf_printk("tcp_send_mss gso: %d, size_goal: %d, ret: %d\n", 
				gso, size, ret);
	}
	return 0;
}

SEC("fexit/tcp_skb_entail")
int BPF_PROG(tcp_skb_entail, struct sock *sk, struct sk_buff *skb)
{
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tcp_skb_entail wmem: %d, sndbuf: %d\n", 
				sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}

SEC("fentry/tcp_push_one")
int BPF_PROG(tcp_push_one, struct sock *sk, unsigned int mss_now)
{
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tcp_push_one wmem: %d, sndbuf: %d\n", 
				sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}

SEC("fentry/__tcp_push_pending_frames")
int BPF_PROG(__tcp_push_pending_frames, struct sock *sk, unsigned int cur_mss, int nonagle)
{
	// // pull in details
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }
	
	if(lport == 8080)
	{
		bpf_printk("tcp_push_one wmem: %d, sndbuf: %d\n", 
				sk_wmem_queued, sk_sndbuf);
	}
	return 0;
}

static int trace_tcp(const struct sock *sk, const struct sk_buff *skb, int rxtx)
{
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	unsigned int skb_data_len = BPF_CORE_READ(skb, data_len);
	unsigned int skb_len = BPF_CORE_READ(skb, len);
	int true_size = BPF_CORE_READ(skb, truesize);
	int sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
	int sk_sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	if (family != AF_INET) {
        return 0;
    }

	if(lport != targ_lport && targ_lport)
		return 0;

	struct tuple_key key = {0};
	key.daddr = daddr;
	key.saddr = saddr;
	key.dport = dport;
	key.lport = lport;

	/* if we recorded start of the process, calculate lifetime duration */
	struct tuple_val *pval;
	pval = bpf_map_lookup_elem(&start, &key);
	if(!pval)
		return 0;

	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->saddr = saddr;
	e->daddr = daddr;
	e->lport = lport;
	e->dport = dport;
	e->af = family;
	e->size_goal = pval->size_goal;
	e->mss = pval->mss;
	e->skb_len = skb_len;
	e->wmem = sk_wmem_queued;
	e->true_size = true_size;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->rxtx = rxtx;
	e->skb_data_len = skb_data_len;
	bpf_ringbuf_submit(e, 0);
	return 0;
}


SEC("fentry/ip_queue_xmit")
int BPF_PROG(ip_queue_xmit, struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	return trace_tcp(sk, skb, 0);
}

SEC("fexit/tcp_ack")
int BPF_PROG(tcp_ack, struct sock *sk, const struct sk_buff *skb, int flag)
{
	return trace_tcp(sk, skb, 1);
}


SEC("tracepoint/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	u16 sport = (u16)ctx->sport;
	u16 dport = (u16)ctx->dport;
	u16 family = (u16)ctx->family;
	u16 data_len = (u16)ctx->data_len;
	u32 snd_nxt = (u32)ctx->snd_nxt;
	u32 snd_una = (u32)ctx->snd_una;
	u32 snd_cwnd = (u32)ctx->snd_cwnd;
	u32 ssthresh = (u32)ctx->ssthresh;
	u32 rcv_wnd = (u32)ctx->rcv_wnd;

	if (family != AF_INET) {
        return 0;
    }

	if(sport == 8080 || dport == 8080)
	{
		bpf_printk("handle_tcp_probe data_len: %u, snd_cwnd: %u, rcv_wnd: %u, snd_nxt: %u, snd_una: %u\n", 
				data_len, snd_cwnd, rcv_wnd, snd_nxt, snd_una);
	}
	return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct sock *sk = (struct sock *)ctx->skaddr;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	struct tuple_val *pval;
	struct tuple_val val = {};

	if (ctx->protocol != IPPROTO_TCP)
		return 0;


	if (family != AF_INET) {
        return 0;
    }

	if(lport != targ_lport && targ_lport)
		return 0;
	
	bpf_printk("handle_sock_set_state,state: %d, lport: %d, dport: %d, saddr: %u, daddr: %u\n", 
				ctx->newstate, lport, dport, saddr, daddr);

	struct tuple_key key = {0};
	key.daddr = daddr;
	key.saddr = saddr;
	key.dport = dport;
	key.lport = lport;

	pval = bpf_map_lookup_elem(&start, &key);
	if(!pval)
	{
		pval = &val;
	}

	if (ctx->newstate == TCP_CLOSE)
		bpf_map_delete_elem(&start, &key);
	else if(ctx->newstate == TCP_ESTABLISHED)
	{
		bpf_map_update_elem(&start, &key, pval, BPF_ANY);
	}
	return 0;
}
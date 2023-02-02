/*
    Flows v2. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
        4) When hash collision is detected, we send the new entry to userpace via ringbuffer.
*/


#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_tracing.h>

#include "probes.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} connections SEC(".maps");

// inet_csk: inet connection sock
/*
SEC("kretprobe/inet_csk_accept")
int tcp_v4_rcv(struct pt_regs *ctx) {
    bpf_printk("entering inet_csk_accept");
    long err = 0;
    
    // TODO: check if there is any way to get this platform-independently (so we can avoid -target x86 in the bpf2go)
    struct sock *sk =(struct sock *)PT_REGS_RC(ctx); // also: (struct sock*)(ctx->ax);
    if (sk == NULL) return 0;

    err = bpf_probe_read_kernel(&rip, sizeof(u16), &sk->__sk_common.skc_num);
    if (err != 0) {
        bpf_printk("error skb: %ld", err);
    } else {
        bpf_printk("receiving tracatraca: %lx %lx", ctx, rip);
    }

    return 0;
}
*/

// Structure according to cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
// More info at: https://stackoverflow.com/questions/75300106/ebpf-verifier-r1-is-not-a-scalar/75302692#75302692
struct set_state_args {
    u64 pad;

    const void * skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
} __attribute__((packed));

typedef struct state_info_t {
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 protocol;
    __u64 time_ns;
} __attribute__((packed)) state_info;
// Force emitting struct sock_info into the ELF.
const state_info *unused __attribute__((unused));

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct set_state_args *args) {
    u64 current_time = bpf_ktime_get_ns();
    state_info *info = bpf_ringbuf_reserve(&connections, sizeof(state_info), 0);
    if (!info) {
        bpf_printk("can't reserve ringbuf space");
        return 0;
    }
    // https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

    info->dport = args->dport; // Destination port is big endian, it must be flipped in x86
    info->sport = args->sport;
    info->protocol = args->protocol;
    info->newstate = args->newstate;
    info->time_ns = current_time;

    bpf_ringbuf_submit(info, 0);
    return 0;
}
char _license[] SEC("license") = "GPL";

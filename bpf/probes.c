#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_tracing.h>

#include "probes.h"

// The ringbuffer is used to forward messages directly to the user space (Go program)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} connections SEC(".maps");

// The data in this struct provides information that is going to be sent to the user space
// via the above ringbuffer.
// The Cilium bpf2go tool will generate a binary-compatible Go clone in pkg/ebpf/bpf_bpfel.go:16
typedef struct state_info_t {
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 protocol;
    __u64 time_ns;
} __attribute__((packed)) state_info;
// Force emitting struct sock_info into the ELF.
const state_info *unused __attribute__((unused));

// This structure contains the arguments of the tracepoint below.
// Its structure must be taken from /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
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

// The actual code that is going to be executed each time the inet_sock_set_state tracepoint is
// triggered. It parses the connection information from the argument and forwards it to the user
// space via ring buffer
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

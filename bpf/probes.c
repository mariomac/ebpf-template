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


#include <sys/socket.h>

#include <common.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "probes.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} connections SEC(".maps");

typedef struct sock_info_t {
    s64 syscall_nr;
    s64 fd;
    struct sockaddr upeer_sockaddr;
    s64 upeer_addrlen;
    s64 flags;
} __attribute__((packed)) sock_info;
// Force emitting struct sock_info into the ELF.
const sock_info *unused __attribute__((unused));

// Structure according to cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
// More info at: https://stackoverflow.com/questions/75300106/ebpf-verifier-r1-is-not-a-scalar/75302692#75302692
// field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// field:int common_pid;	offset:4;	size:4;	signed:1;

// field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// field:int fd;	offset:16;	size:8;	signed:0;
// field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
// field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
// field:int flags;	offset:40;	size:8;	signed:0;
struct accept4_args {
    u64 pad;

    s64 __syscall_nr;
    s64 fd;
    struct sockaddr *upeer_sockaddr;
    s64 *upeer_addrlen;
    s64 flags;
};

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct accept4_args *args) {
    sock_info *iad = bpf_ringbuf_reserve(&connections, sizeof(sock_info), 0);
    if (!iad) {
        bpf_printk("can't reserve ringbuf space");
        return 0;
    }
    // https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

    iad->syscall_nr = args->__syscall_nr;
    iad->fd = args->fd;
    iad->flags = args->flags;

    long err = bpf_probe_read(&iad->upeer_sockaddr, sizeof(struct sockaddr), &args->upeer_sockaddr);
    if (err != 0) {
        bpf_printk("error reading sa_data: %ld", err);
    }

    // err = bpf_probe_read(&iad->sadata, sizeof(iad->sadata), args->upeer_sockaddr->sa_data);
    // if (err != 0) {
    //     bpf_printk("error reading sadata: %ld", err);
    // }

    err = bpf_probe_read_kernel(&iad->upeer_addrlen, sizeof(s64), &args->upeer_addrlen);
    if (err != 0) {
        bpf_printk("error reading addrlen: %ld", err);
    }

    bpf_ringbuf_submit(iad, 0);
    return 0;
}
char _license[] SEC("license") = "GPL";

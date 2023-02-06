For prototyping, [`bpftrace` tool](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
helps you quickly preview the behavior of some probes and tracepoints.

Look for a given hook:
```
sudo bpftrace -l "*accept4*"
kfunc:__ia32_sys_accept4
kfunc:__sys_accept4
kfunc:__sys_accept4_file
kfunc:__x64_sys_accept4
kprobe:__ia32_sys_accept4
kprobe:__sys_accept4
kprobe:__sys_accept4_file
kprobe:__x64_sys_accept4
tracepoint:syscalls:sys_enter_accept4
tracepoint:syscalls:sys_exit_accept4
```

E.g. this allows to see how the `tracepoint:syscalls:sys_enter_accept4` hook works every
time the host accepts a CONNECTION:

```
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_accept4 { printf("accepted stuff\n"); }'
```

If we want to show more info, we can first check for the format of the arguments of that
syscall:

```
# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept4/format
name: sys_enter_accept4
ID: 1432
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
	field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
	field:int flags;	offset:40;	size:8;	signed:0;

print fmt: "fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->upeer_sockaddr)), ((unsigned long)(REC->upeer_addrlen)), ((unsigned long)(REC->flags))

# bpftrace -e 'tracepoint:syscalls:sys_enter_accept4 { printf("fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx, flags: 0x%08lx\n", args->fd, args->upeer_sockaddr, args->upeer_addrlen, args->flags); }'
Attaching 1 probe...
fd: 0x00000003, upeer_sockaddr: 0xc000195ab8, upeer_addrlen: 0xc000195aa4, flags: 0x00080800
fd: 0x00000003, upeer_sockaddr: 0xc000195ab8, upeer_addrlen: 0xc000195aa4, flags: 0x00080800
fd: 0x00000003, upeer_sockaddr: 0xc000195ab8, upeer_addrlen: 0xc000195aa4, flags: 0x00080800
```

# Tracepoint arguments

You have to create a struct emulating the above structure:

```
struct accept4_args {
    u64 pad;

    s64 __syscall_nr;
    u64 fd;
    struct sockaddr *upeer_sockaddr;
    u64 *upeer_addrlen;
    u64 flags;
};
```


That can be used as argument:

```
SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct accept4_args *args) {
```


# Kprobes arguments

A pt_regs struct must be passed as pointer:

```
SEC("kprobe/inet_accept")
int sys_probe_accept4(struct pt_regs *regs) {
```

Then arguments can be accessed as:

```
    int *fd = (int*)PT_REGS_PARM1(regs);
    bpf_probe_read(&args->fd, sizeof(u64), fd);
```

To make use of `PT_REGS_PARM1` and so on, the bpf2go has now to be compiled with -target amd64 or arm64

## Simpler alternative

```
SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(inet_csk_accept,
    struct sock *sk,
    int flags,
    int *err,
    bool kern) {
```

However this doesn't allow more than 6 arguments. It still forces you using
`bpf_probe_read` for e.g. sk.

## Debugging

```
# llvm-objdump -S --no-show-raw-insn pkg/ebpf/bpf_bpfeb.o

pkg/ebpf/bpf_bpfeb.o:	file format elf64-bpf

Disassembly of section tracepoint/syscalls/sys_enter_accept4:

0000000000000000 <inet_accept>:
       0:	r3 = r1
       1:	if r2 == 0 goto +7 <LBB0_2>
       2:	r4 = *(u8 *)(r2 + 2)
       3:	r4 <<= 56
       4:	r4 s>>= 56
       5:	r1 = 0 ll
       7:	r2 = 47
       8:	call 6

0000000000000048 <LBB0_2>:
       9:	r0 = 0
      10:	exit
```
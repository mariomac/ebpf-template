package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type sock_info bpf ../../bpf/probes.c -- -I../../bpf/headers

const mapKey uint32 = 0

func Trace() {
	// Allow the current process to lock memory for eBPF resources.
	log.Println("start tracer")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	log.Println("load BPF object")
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		verr := &ebpf.VerifierError{}
		if !errors.As(err, &verr) {
			log.Fatal("loading objects", err)
		}
		log.Println("cause", verr.Cause)
		for _, l := range verr.Log {
			fmt.Println(l)
		}
		log.Fatal("loading objects", verr)
		return
	}
	defer objs.Close()

	log.Println("registering tracepoint")
	kp, err := link.Tracepoint("syscalls", "sys_enter_accept4", objs.SysEnterAccept4, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Connections)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Println("Waiting for events..")

	var conn bpfSockInfo
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &conn); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("%#v", conn)

		buf := bytes.Buffer{}
		binary.Write(&buf, binary.LittleEndian, conn)

		ibuf := make([]byte, buf.Len())
		for i, b := range buf.Bytes() {
			ibuf[len(ibuf)-i-1] = b
		}

		//binary.Read(bytes.NewReader(ibuf), binary.BigEndian, &conn)
		//log.Printf("invert: %#v", conn)

		//log.Printf("%d.%d.%d.%d",
		//	conn.SaData[0],
		//	conn.SaData[1],
		//	conn.SaData[2],
		//	conn.SaData[3])

	}
}

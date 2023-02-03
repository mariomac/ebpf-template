package tracker

import (
	"time"

	"github.com/gavv/monotime"
	tracer "github.com/mariomac/ebpf-template/pkg/ebpf"
	"golang.org/x/exp/slog"
)

// values according to net/tcp_states.h
const (
	tcpEstablished = 1
	tcpClose       = 7
)

type ConnectionSpan struct {
	SrcPort int
	DstPort int
	Start   time.Time
	End     time.Time
}

// TODO: for proper performance, this aggregation should be done at kernel side
func Track(in <-chan tracer.SockStateInfo, out chan<- ConnectionSpan) {
	conns := newConnections()
	for update := range in {
		if trace, ok := conns.newEvent(update); ok {
			out <- trace
		}
	}
}

type connKey struct {
	SrcPort uint16
	DstPort uint16
}

type connections struct {
	clock     func() time.Time
	monoClock func() time.Duration
	traces    map[connKey]ConnectionSpan
}

func newConnections() connections {
	return connections{
		traces:    map[connKey]ConnectionSpan{},
		monoClock: monotime.Now,
		clock:     time.Now,
	}
}

func (c *connections) newEvent(e tracer.SockStateInfo) (toSubmit ConnectionSpan, flush bool) {
	key := connKey{
		SrcPort: e.Sport,
		DstPort: e.Dport,
	}
	now := time.Now()
	monoNow := c.monoClock()
	switch e.Newstate {
	case tcpEstablished:
		slog.Debug("connection established state",
			"srcPort", key.SrcPort, "dstPort", key.DstPort, "protocol", e.Protocol)
		startDelta := monoNow - time.Duration(e.TimeNs)
		c.traces[key] = ConnectionSpan{
			SrcPort: int(e.Sport),
			DstPort: int(e.Dport),
			Start:   now.Add(-startDelta),
		}
	case tcpClose:
		slog.Debug("connection closed state",
			"srcPort", key.SrcPort, "dstPort", key.DstPort, "protocol", e.Protocol)
		if trace, ok := c.traces[key]; ok {
			delete(c.traces, key)
			endDelta := monoNow - time.Duration(e.TimeNs)
			trace.End = now.Add(-endDelta)
			return trace, true
		}
		slog.Debug("received close update of a socket that was not registered",
			"srcPort", key.SrcPort, "dstPort", key.DstPort, "protocol", e.Protocol)
	default:
		slog.Debug("ignoring state update",
			"status", e.Newstate,
			"srcPort", key.SrcPort, "dstPort", key.DstPort, "protocol", e.Protocol)
	}
	return
}

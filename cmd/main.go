package main

import (
	"fmt"
	"github.com/mariomac/ebpf-template/pkg/otel"
	"os"

	tracer "github.com/mariomac/ebpf-template/pkg/ebpf"
	"github.com/mariomac/ebpf-template/pkg/tracker"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

func main() {
	ho := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))
	traceFunc, err := tracer.Trace()
	if err != nil {
		panic(err)
	}
	traceNode := node.AsStart(traceFunc)
	trackerNode := node.AsMiddle(tracker.Track)
	printerNode := node.AsTerminal(func(spans <-chan tracker.ConnectionSpan) {
		for span := range spans {
			fmt.Printf("connection %s long: %#v\n", span.End.Sub(span.Start), span)
		}
	})
	report, err := otel.Report("localhost:4318")
	if err != nil {
		panic(err)
	}
	otelNode := node.AsTerminal(report)
	traceNode.SendsTo(trackerNode)
	trackerNode.SendsTo(printerNode)
	trackerNode.SendsTo(otelNode)
	slog.Info("Starting main node")
	traceNode.Start()
	wait := make(chan struct{})
	<-wait
}

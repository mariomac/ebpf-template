package otel

import (
	"context"
	"fmt"

	"github.com/mariomac/ebpf-template/pkg/tracker"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	trace2 "go.opentelemetry.io/otel/trace"
)

func Report(endpoint string) (func(<-chan tracker.ConnectionSpan), error) {
	report := reporter{endpoint: endpoint}
	if err := report.start(); err != nil {
		return nil, fmt.Errorf("instantiating OTEL: %w", err)
	}
	// TODO: make configurable
	return func(spans <-chan tracker.ConnectionSpan) {
		tracer := report.provider.Tracer("github.com/mariomac/otel-go-grafana")
		for span := range spans {
			// TODO: there must be a better way to instantiate spans
			_, sp := tracer.Start(context.TODO(), "session",
				trace2.WithTimestamp(span.Start),
				trace2.WithAttributes(
					attribute.Int("src.port", span.SrcPort),
					attribute.Int("dst.port", span.DstPort),
				),
				// TODO: trace2.WithSpanKind()
			)
			sp.End(trace2.WithTimestamp(span.End))
		}
	}, nil
}

type reporter struct {
	endpoint string
	exporter *otlptrace.Exporter
	provider *trace.TracerProvider
}

func (r *reporter) start() error {
	ctx := context.TODO()

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String("otel-ebpf-sockets"),
		semconv.ServiceVersionKey.String("v0.0.0"),
	)

	// Instantiate the OTLP HTTP exporter
	// TODO: better use GRPC (secure)
	var err error
	r.exporter, err = otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(r.endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return err
	}
	r.provider = trace.NewTracerProvider(
		trace.WithResource(resources),
		trace.WithSyncer(r.exporter),
	)
	return nil
}

func (r *reporter) Close() error {
	if err := r.provider.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("closing traces provider: %w", err)
	}
	if err := r.exporter.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("closing traces exporter: %w", err)
	}
	return nil
}

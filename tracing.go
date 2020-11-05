package main

import (
	"context"
	"net/http"
	"os"

	"contrib.go.opencensus.io/exporter/jaeger"
	"github.com/go-chi/chi"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	datadog "github.com/DataDog/opencensus-go-exporter-datadog"
	spanlog "github.com/oneconcern/keycloak-gatekeeper/internal/log"
)

// Logger is a simplified abstraction of the zap.Logger
type Logger interface {
	Debug(msg string, fields ...zapcore.Field)
	Info(msg string, fields ...zapcore.Field)
	Warn(msg string, fields ...zapcore.Field)
	Error(msg string, fields ...zapcore.Field)
	Fatal(msg string, fields ...zapcore.Field)
}

// proxyTracingHandler forwards the request to the opencensus tracing handler
func (r *oauthProxy) proxyTracingMiddleware(next http.Handler) http.Handler {
	if !r.config.EnableTracing {
		return next
	}
	const svc = "gatekeeper"

	switch r.config.TracingExporter {
	case "jaeger":
		// set up span exporter
		je, err := jaeger.NewExporter(jaeger.Options{
			AgentEndpoint: os.ExpandEnv(r.config.TracingAgentEndpoint),
			ServiceName:   svc,
		})
		if err != nil {
			r.log.Warn("jaeger trace span exporting disabled", zap.Error(err))
			r.config.EnableTracing = false
			return next
		}
		trace.RegisterExporter(je)
		r.log.Info("jaeger trace span exporting enabled")
	case "datadog":
		exporterError := func(err error) {
			r.log.Warn("could not export trace to datadog agent", zap.Error(err))
		}
		service := os.Getenv("DD_SERVICE")
		if service == "" {
			service = svc
		}
		ns := os.Getenv("DD_NAMESPACE")
		// enable trace exporting to datadog agent
		de, err := datadog.NewExporter(datadog.Options{
			Namespace: ns,
			Service:   service,
			TraceAddr: os.ExpandEnv(r.config.TracingAgentEndpoint),
			OnError:   exporterError,
			GlobalTags: map[string]interface{}{
				"env":       os.Getenv("DD_ENV"),
				"version":   os.Getenv("DD_VERSION"),
				"namespace": ns,
			},
		})
		if err != nil {
			r.log.Info("datadog reporting disabled", zap.Error(err))
			r.config.EnableTracing = false
			return next
		}
		trace.RegisterExporter(de)
		r.log.Info("datadog trace span exporting enabled")
	default:
		r.log.Warn("tracing is enabled, but no supported exporter is configured. Tracing disabled")
	}
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	// insert instrumentation middleware
	instrument1 := func(next http.Handler) http.Handler {
		return &ochttp.Handler{
			Handler:          next,
			Propagation:      &b3.HTTPFormat{},
			IsPublicEndpoint: true,
		}
	}
	instrument2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := chi.RouteContext(r.Context())
			ochttp.WithRouteTag(next, route.RoutePath).ServeHTTP(w, r)
		})
	}
	return instrument1(instrument2(next))
}

func (r *oauthProxy) traceSpan(ctx context.Context, title string) (context.Context, *trace.Span, Logger) {
	if !r.config.EnableTracing {
		return ctx, nil, r.log
	}
	newCtx, span := trace.StartSpan(ctx, title)
	return newCtx, span, spanlog.New(r.log, span)
}

func (r *oauthProxy) traceSpanRequest(req *http.Request) (*trace.Span, Logger) {
	if !r.config.EnableTracing {
		return nil, r.log
	}
	span := trace.FromContext(req.Context())

	if span != nil {
		return span, spanlog.New(r.log, span)
	}
	return span, r.log
}

func traceError(span *trace.Span, err error, code int) error {
	var traceCode int32
	switch err {
	case context.Canceled:
		traceCode = trace.StatusCodeCancelled
	case context.DeadlineExceeded:
		traceCode = trace.StatusCodeDeadlineExceeded
	default:
		switch code {
		case http.StatusForbidden:
			traceCode = trace.StatusCodePermissionDenied
		case http.StatusUnauthorized:
			traceCode = trace.StatusCodeUnauthenticated
		case http.StatusNotFound:
			traceCode = trace.StatusCodeNotFound
		case http.StatusBadRequest:
			traceCode = trace.StatusCodeInvalidArgument
		case http.StatusInternalServerError:
			traceCode = trace.StatusCodeInternal
		default:
			traceCode = trace.StatusCodeUnknown
		}
	}
	if err == nil {
		span.SetStatus(trace.Status{
			Code: traceCode,
		})
	} else {
		span.SetStatus(trace.Status{
			Code:    traceCode,
			Message: err.Error(),
		})
	}
	return err
}

func propagateSpan(span *trace.Span, req *http.Request) {
	// B3 span propagation (e.g. Opentracing)
	// NOTE: datadog is supposed support opentracing headers
	propagation := &b3.HTTPFormat{}
	propagation.SpanContextToRequest(span.SpanContext(), req)

}

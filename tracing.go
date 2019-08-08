package main

import (
	"context"
	"net/http"

	"contrib.go.opencensus.io/exporter/jaeger"
	"github.com/go-chi/chi"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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

	// set up span exporter
	je, err := jaeger.NewExporter(jaeger.Options{
		AgentEndpoint: r.config.TracingAgentEndpoint,
		ServiceName:   "gatekeeper",
	})
	if err != nil {
		r.log.Info("jaeger trace span exporting disabled", zap.Error(err))
	} else {
		r.log.Info("jaeger trace span exporting enabled")
	}
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
	trace.RegisterExporter(je)

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
	return newCtx, span, spanLogger(ctx, r.log)
}

func (r *oauthProxy) traceSpanRequest(req *http.Request) (*trace.Span, Logger) {
	if !r.config.EnableTracing {
		return nil, r.log
	}
	return trace.FromContext(req.Context()), spanLogger(req.Context(), r.log)
}

// spanLogger wraps the logger with some trace span exporting
func spanLogger(ctx context.Context, logger *zap.Logger) Logger {
	if span := trace.FromContext(ctx); span != nil {
		return spanlog.New(logger, span)
	}
	return logger
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
	span.SetStatus(trace.Status{
		Code:    traceCode,
		Message: err.Error(),
	})
	return err
}

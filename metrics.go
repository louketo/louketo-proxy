package main

import (
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	certificateRotationMetric = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_certificate_rotation_total",
			Help: "The total amount of times the certificate has been rotated",
		},
	)
	oauthTokensMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_oauth_tokens_total",
			Help: "A summary of the tokens issued, renewed or failed logins",
		},
		[]string{"action"},
	)
	oauthLatencyMetric = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "proxy_oauth_request_latency_sec",
			Help: "A summary of the request latancy for requests against the openid provider",
		},
		[]string{"action"},
	)
	latencyMetric = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "proxy_request_duration_sec",
			Help: "A summary of the http request latency for proxy requests",
		},
	)
	statusMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_request_status_total",
			Help: "The HTTP requests partitioned by status code",
		},
		[]string{"code", "method"},
	)
)

func init() {
	prometheus.MustRegister(certificateRotationMetric)
	prometheus.MustRegister(latencyMetric)
	prometheus.MustRegister(oauthLatencyMetric)
	prometheus.MustRegister(oauthTokensMetric)
	prometheus.MustRegister(statusMetric)
}

func (r *oauthProxy) metricsHandler() http.Handler {
	if !r.config.EnableMetrics {
		return nil
	}
	return promhttp.Handler()
}

// proxyMetricsHandler forwards the request to the prometheus handler
func (r *oauthProxy) proxyMetricsHandler(w http.ResponseWriter, req *http.Request) {
	if !r.config.EnableMetrics {
		return
	}
	if r.config.LocalhostMetrics {
		// option to only give access to a localhost metrics collection agent
		if !net.ParseIP(realIP(req)).IsLoopback() {
			r.accessForbidden(w, req)
			return
		}
	}
	r.metricsHandler().ServeHTTP(w, req)
}

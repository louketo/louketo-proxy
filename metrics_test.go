package main

import (
	"net/http"
	"testing"
)

func TestMetricsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableMetrics = true
	cfg.LocalhostMetrics = true
	requests := []fakeRequest{
		{
			URI:                     cfg.WithOAuthURI(metricsURL),
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "proxy_request_status_total",
		},
		{
			URI: cfg.WithOAuthURI(metricsURL),
			Headers: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			ExpectedCode: http.StatusForbidden,
		},
	}
	newFakeProxy(cfg).RunTests(t, requests)
}

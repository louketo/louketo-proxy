/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeUpstreamService acts as a fake upstream service, returns the headers and request
type counterService struct {
	Name       string
	HitCounter int64
}

func (f *counterService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("counter %s\n", f.Name)
	atomic.AddInt64(&f.HitCounter, 1)
}

//TestWebSocket is used to validate that the proxy reverse proxy WebSocket connections.
func TestUpstreamPaths(t *testing.T) {
	// Setup an upstream service.
	defaultSvc := &counterService{Name: "default"}

	defaultSvcServer := httptest.NewServer(defaultSvc)
	defer defaultSvcServer.Close()

	adminSvc := &counterService{Name: "admin"}

	adminSvcServer := httptest.NewServer(adminSvc)
	defer adminSvcServer.Close()

	dataSvc := &counterService{Name: "data"}

	dataSvcServer := httptest.NewServer(dataSvc)
	defer dataSvcServer.Close()

	counters := func() []int64 {
		return []int64{
			atomic.AddInt64(&defaultSvc.HitCounter, 0),
			atomic.AddInt64(&adminSvc.HitCounter, 0),
			atomic.AddInt64(&dataSvc.HitCounter, 0),
		}
	}

	// Setup the proxy.
	config := newFakeKeycloakConfig()
	config.Upstream = defaultSvcServer.URL
	config.UpstreamPaths = []UpstreamURLPath{
		{
			URL:      "/auth_all/white_listed/admin",
			Upstream: adminSvcServer.URL,
		},
		{
			URL:      "/auth_all/white_listed/data",
			Upstream: dataSvcServer.URL,
		},
	}

	auth := newFakeAuthServer()
	config.DiscoveryURL = auth.getLocation()
	config.RevocationEndpoint = auth.getRevocationURL()

	proxy, err := newProxy(config)
	require.NoError(t, err)

	proxyServer := httptest.NewServer(proxy.router)
	defer proxyServer.Close()

	resp, err := http.Get(proxyServer.URL + "/auth_all/white_listed/admin")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, []int64{0, 1, 0}, counters())

	resp, err = http.Get(proxyServer.URL + "/auth_all/white_listed/other")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, []int64{1, 1, 0}, counters())

	resp, err = http.Get(proxyServer.URL + "/auth_all/white_listed/data")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, []int64{1, 1, 1}, counters())
}

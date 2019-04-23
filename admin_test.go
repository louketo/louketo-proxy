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
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	e2eAdminProxyListener    = "127.0.0.1:24329"
	e2eAdminEndpointListener = "127.0.0.1:24330"

	e2eAdminProxyListener2 = "127.0.0.1:44329"

	e2eAdminOauthListener    = "127.0.0.1:23457"
	e2eAdminUpstreamListener = "127.0.0.1:28512"
	e2eAdminAppListener      = "127.0.0.1:33996"

	e2eAdminAppURL      = "/ok"
	e2eAdminUpstreamURL = "/fake"

	secretForCookie = "A123456789B123456789C123456789D1"
)

func testBuildAdminConfig() *Config {
	config := newDefaultConfig()
	config.Verbose = false
	config.DisableAllLogging = false
	config.EnableLogging = false

	config.Listen = e2eAdminProxyListener
	config.ListenAdmin = e2eAdminEndpointListener
	config.EnableMetrics = true
	config.EnableProfiling = true
	config.DiscoveryURL = testDiscoveryURL(e2eAdminOauthListener, "hod-test")
	config.Upstream = "http://" + e2eAdminUpstreamListener

	config.CorsOrigins = []string{"*"}
	config.EnableCSRF = false
	config.HTTPOnlyCookie = false // since we want to inspect the cookie for testing
	config.SecureCookie = false   // since we are testing over HTTP
	config.AccessTokenDuration = 30 * time.Minute
	config.EnableEncryptedToken = false
	config.EnableSessionCookies = true
	config.EnableAuthorizationCookies = false
	config.EnableClaimsHeaders = false
	config.EnableTokenHeader = false
	config.EnableAuthorizationHeader = true
	config.ClientID = fakeClientID
	config.ClientSecret = fakeSecret
	config.Resources = []*Resource{
		{
			URL:         "/fake",
			Methods:     []string{"GET", "POST", "DELETE"},
			WhiteListed: false,
			EnableCSRF:  false,
		},
	}
	config.Resources = append(config.Resources, &Resource{
		URL:         "/another-fake",
		Methods:     []string{"GET", "POST", "DELETE"},
		WhiteListed: false,
		EnableCSRF:  false,
	})
	config.EncryptionKey = secretForCookie
	return config
}

func TestAdmin(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	config := testBuildAdminConfig()
	if !assert.NoError(t, config.isValid()) {
		t.FailNow()
	}

	// launch fake oauth OIDC server
	err := runTestAuth(t, e2eAdminOauthListener, "hod-test")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch fake upstream resource server
	err = runTestUpstream(t, e2eAdminUpstreamListener, e2eAdminUpstreamURL)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch fake app server where to land after authentication
	err = runTestApp(t, e2eAdminAppListener, e2eAdminAppURL)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch keycloak-gatekeeper proxy
	err = runTestGatekeeper(t, config)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// scenario 1: dedicated admin port

	// test health status endpoint
	client := http.Client{}
	u, _ := url.Parse("http://" + e2eAdminEndpointListener + "/oauth/health")
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	h.Add("Accept", "application/json")
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}

	resp, err := client.Do(req)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb := ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.Equal(t, "OK\n", string(buf)) // check this is our test resource being called

	// test prometheus metrics endpoint
	u, _ = url.Parse("http://" + e2eAdminEndpointListener + "/oauth/metrics")
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}

	resp, err = client.Do(req)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb = ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.Contains(t, string(buf), `proxy_request_duration_sec`)

	// test profiling/debug endpoint
	u, _ = url.Parse("http://" + e2eAdminEndpointListener + debugURL + "/symbol")
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}

	resp, err = client.Do(req)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb = ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.Contains(t, string(buf), "num_symbols: 1\n")

	// scenario 2: admin endpoints next to other routes (same listener)
	config.Listen = e2eAdminProxyListener2
	config.ListenAdmin = ""
	config.LocalhostMetrics = true

	// launch a new keycloak-gatekeeper proxy
	err = runTestGatekeeper(t, config)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// test health status endpoint, unauthenticated
	u, _ = url.Parse("http://" + e2eAdminProxyListener2 + "/oauth/health")
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}
	resp, err = client.Do(req)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb = ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.Contains(t, string(buf), `OK`)

	// test metrics
	u, _ = url.Parse("http://" + e2eAdminProxyListener2 + "/oauth/metrics")
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}

	resp, err = client.Do(req)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb = ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.Contains(t, string(buf), `proxy_request_duration_sec`)
}

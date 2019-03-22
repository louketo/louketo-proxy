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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
)

const (
	e2eAdminProxyListener    = "127.0.0.1:24329"
	e2eAdminEndpointListener = "127.0.0.1:24330"

	e2eAdminProxyListener2 = "127.0.0.1:44329"

	e2eAdminOauthListener     = "127.0.0.1:23457"
	e2eAdminUpstreamListener  = "127.0.0.1:28512"
	e2eAdminAppListener       = "127.0.0.1:33996"
	e2eAdminOauthURL          = "/auth/realms/hod-test/.well-known/openid-configuration"
	e2eAdminOauthAuthorizeURL = "/auth/realms/hod-test/protocol/openid-connect/auth"
	// #nosec
	e2eAdminOauthTokenURL = "/auth/realms/hod-test/protocol/openid-connect/token"
	e2eAdminOauthJWKSURL  = "/auth/realms/hod-test/protocol/openid-connect/certs"
	e2eAdminAppURL        = "/ok"
)

// checkListenOrBail waits on a endpoint listener to respond.
// This avoids race conditions with test listieners as go routines
func checkListenOrBail(endpoint string) bool {
	const (
		maxWaitCycles = 10
		waitTime      = 100 * time.Millisecond
	)
	checkListen := http.Client{}
	_, err := checkListen.Get(endpoint)
	limit := 0
	for err != nil && limit < maxWaitCycles {
		time.Sleep(waitTime)
		_, err = checkListen.Get(endpoint)
		limit++
	}
	return limit < maxWaitCycles
}

func runAdminTestAuth(t *testing.T) error {
	// a stub OIDC provider
	fake := newFakeAuthServer()
	fake.location, _ = url.Parse("http://" + e2eAdminOauthListener)
	go func() {
		mux := http.NewServeMux()
		configurationHandler := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"issuer": "http://`+e2eAdminOauthListener+`/auth/realms/hod-test",
				"subject_types_supported":["public","pairwise"],
				"id_token_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512"],
				"userinfo_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512","none"],
				"authorization_endpoint":"http://`+e2eAdminOauthListener+e2eAdminOauthAuthorizeURL+`",
				"token_endpoint":"http://`+e2eAdminOauthListener+e2eAdminOauthTokenURL+`",
				"jwks_uri":"http://`+e2eAdminOauthListener+e2eAdminOauthJWKSURL+`"
			}`)
		}

		authorizeHandler := func(w http.ResponseWriter, req *http.Request) {
			redirect := req.FormValue("redirect_uri")
			state := req.FormValue("state")
			code := "zyx"
			location, _ := url.PathUnescape(redirect)
			u, _ := url.Parse(location)
			v := u.Query()
			v.Set("code", code)
			v.Set("state", state)
			u.RawQuery = v.Encode()
			http.Redirect(w, req, u.String(), http.StatusFound)
		}

		tokenHandler := func(w http.ResponseWriter, req *http.Request) {
			fake.tokenHandler(w, req)
		}

		keysHandler := func(w http.ResponseWriter, req *http.Request) {
			fake.keysHandler(w, req)
		}
		mux.HandleFunc(e2eAdminOauthURL, configurationHandler)
		mux.HandleFunc(e2eAdminOauthAuthorizeURL, authorizeHandler)
		mux.HandleFunc(e2eAdminOauthTokenURL, tokenHandler)
		mux.HandleFunc(e2eAdminOauthJWKSURL, keysHandler)
		_ = http.ListenAndServe(e2eAdminOauthListener, mux)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eAdminOauthListener, e2eAdminOauthURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eAdminOauthListener, e2eAdminOauthURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func runAdminTestApp(t *testing.T) error {
	go func() {
		mux := http.NewServeMux()
		appHandler := func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"message": "ok"}`)
			w.Header().Set("Content-Type", "application/json")
		}
		mux.HandleFunc(e2eAdminAppURL, appHandler)
		_ = http.ListenAndServe(e2eAdminAppListener, mux)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eAdminAppListener, e2eAdminAppURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eAdminAppListener, e2eAdminAppURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func runAdminTestGatekeeper(t *testing.T, config *Config) error {
	proxy, err := newProxy(config)
	if err != nil {
		return err
	}
	_ = proxy.Run()
	if !assert.True(t, checkListenOrBail("http://"+config.Listen+"/oauth/login")) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+config.Listen+"/oauth/login")
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func runAdminTestUpstream(t *testing.T) error {
	// a stub upstream API server
	go func() {
		getUpstream := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Response-Header", "test")
			_, _ = io.WriteString(w, `{"message": "test"}`)
		}

		upstream := chi.NewRouter()
		upstream.Route("/", func(r chi.Router) {
			r.Get("/fake", getUpstream)
		})

		_ = http.ListenAndServe(e2eAdminUpstreamListener, upstream)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eAdminUpstreamListener, "/fake"))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eAdminUpstreamListener, "/fake"))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func TestAdmin(t *testing.T) {
	log.SetOutput(ioutil.Discard)

	config := newDefaultConfig()
	config.Verbose = false
	config.DisableAllLogging = false
	config.EnableLogging = false

	config.Listen = e2eAdminProxyListener
	config.ListenAdmin = e2eAdminEndpointListener
	config.EnableMetrics = true
	config.EnableProfiling = true
	config.DiscoveryURL = "http://" + e2eAdminOauthListener + e2eAdminOauthURL
	config.Upstream = "http://" + e2eAdminUpstreamListener

	config.CorsOrigins = []string{"*"}
	config.HTTPOnlyCookie = false // since we want to inspect the cookie for testing
	config.SecureCookie = false   // since we are testing over HTTP
	config.AccessTokenDuration = 30 * time.Minute
	config.EnableEncryptedToken = false
	config.EnableSessionCookies = true
	config.EnableAuthorizationCookies = false
	config.EnableTokenHeader = false
	config.EnableAuthorizationHeader = true
	config.ClientID = fakeClientID
	config.ClientSecret = fakeSecret
	config.Resources = []*Resource{
		{
			URL:         "/fake",
			Methods:     []string{"GET", "POST", "DELETE"},
			WhiteListed: false,
		},
	}
	config.Resources = append(config.Resources, &Resource{
		URL:         "/another-fake",
		Methods:     []string{"GET", "POST", "DELETE"},
		WhiteListed: false,
	})
	config.EncryptionKey = "A123456789B123456789C123456789D1"
	if !assert.NoError(t, config.isValid()) {
		t.FailNow()
	}

	// launch fake oauth OIDC server
	err := runAdminTestAuth(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch fake upstream resource server
	err = runAdminTestUpstream(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch fake app server where to land after authentication
	err = runAdminTestApp(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch keycloak-gatekeeper proxy
	err = runAdminTestGatekeeper(t, config)
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

	// scenario 2: admin endpoints beside other routes
	config.Listen = e2eAdminProxyListener2
	config.ListenAdmin = ""
	config.LocalhostMetrics = true

	// launch a new keycloak-gatekeeper proxy
	err = runAdminTestGatekeeper(t, config)
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

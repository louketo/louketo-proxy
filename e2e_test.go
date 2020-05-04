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

	"github.com/stretchr/testify/assert"
)

const (
	e2eUpstreamURL      = "/upstream"
	e2eUpstreamListener = "127.0.0.1:12345"
	e2eProxyListener    = "127.0.0.1:54321"
	e2eOauthListener    = "127.0.0.1:23456"
	e2eOauthURL         = "/.well-known/openid-configuration"
)

// checkListenOrBail waits on a endpoint listener to respond.
// This avoids race conditions with test listieners as go routines
func checkListenOrBail(endpoint string) bool {
	const (
		maxWaitCycles = 10
		waitTime      = 100 * time.Millisecond
	)
	checkListen := http.Client{}
	//nolint:bodyclose
	_, err := checkListen.Get(endpoint)
	limit := 0
	for err != nil && limit < maxWaitCycles {
		time.Sleep(waitTime)
		//nolint:bodyclose
		_, err = checkListen.Get(endpoint)
		limit++
	}
	return limit < maxWaitCycles
}

func runTestLouketo(t *testing.T, config *Config) error {
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

func runTestUpstream(t *testing.T) error {
	go func() {
		upstreamHandler := func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"message": "test"}`)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Response-Header", "test")
		}
		http.HandleFunc(e2eUpstreamURL, upstreamHandler)
		_ = http.ListenAndServe(e2eUpstreamListener, nil)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eUpstreamListener, e2eUpstreamURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eUpstreamListener, e2eUpstreamURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func runTestAuth(t *testing.T) error {
	go func() {
		configurationHandler := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"issuer": "http://`+e2eOauthListener+`",
				"subject_types_supported":["public","pairwise"],
				"id_token_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512"],
				"userinfo_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512","none"],
				"authorization_endpoint":"http://`+e2eOauthListener+`/auth/realms/master/protocol/openid-connect/auth",
				"token_endpoint":"http://`+e2eOauthListener+`/auth/realms/master/protocol/openid-connect/token",
				"jwks_uri":"http://`+e2eOauthListener+`/auth/realms/master/protocol/openid-connect/certs"
			}`)
		}
		http.HandleFunc(e2eOauthURL, configurationHandler)
		_ = http.ListenAndServe(e2eOauthListener, nil)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eOauthListener, e2eOauthURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eOauthListener, e2eOauthURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func TestCorsWithUpstream(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	config := newDefaultConfig()
	config.Listen = e2eProxyListener
	config.DiscoveryURL = "http://" + e2eOauthListener + e2eOauthURL
	config.Upstream = "http://" + e2eUpstreamListener
	config.CorsOrigins = []string{"*"}
	config.Verbose = false
	config.DisableAllLogging = true
	config.Resources = []*Resource{
		{
			URL:         e2eUpstreamURL,
			Methods:     []string{"GET"},
			WhiteListed: true,
		},
	}

	// launch fake upstream resource server
	_ = runTestUpstream(t)

	// launch fake oauth OIDC server
	_ = runTestAuth(t)

	// launch louketo-proxy proxy
	_ = runTestLouketo(t, config)

	// ok now exercise the ensemble with a CORS-enabled request
	client := http.Client{}
	u, _ := url.Parse("http://" + e2eProxyListener + e2eUpstreamURL)
	h := make(http.Header, 1)
	h.Set("Content-Type", "application/json")
	h.Add("Origin", "myorigin.com")

	resp, err := client.Do(&http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	})
	assert.NoError(t, err)
	buf, erb := ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.JSONEq(t, `{"message":"test"}`, string(buf)) // check this is our test resource
	if assert.NotEmpty(t, resp.Header) && assert.Contains(t, resp.Header, "Access-Control-Allow-Origin") {
		// check the returned upstream response after proxying contains CORS headers
		assert.Equal(t, []string{"*"}, resp.Header["Access-Control-Allow-Origin"])
	}
	defer resp.Body.Close()
}

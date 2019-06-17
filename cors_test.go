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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	e2eCorsUpstreamListener = "127.0.0.1:12345"
	e2eCorsProxyListener    = "127.0.0.1:54321"
	e2eCorsOauthListener    = "127.0.0.1:23456"

	e2eCorsUpstreamURL = "/upstream"
)

func testBuildCorsConfig() *Config {
	config := newDefaultConfig()
	config.Listen = e2eCorsProxyListener
	config.DiscoveryURL = testDiscoveryURL(e2eCorsOauthListener, "master")
	config.Upstream = "http://" + e2eCorsUpstreamListener
	config.CorsOrigins = []string{"*"}
	config.Verbose = false
	config.EnableLogging = false
	config.DisableAllLogging = true

	config.Resources = []*Resource{
		{
			URL:         e2eCorsUpstreamURL,
			Methods:     []string{"GET"},
			WhiteListed: true,
		},
	}
	return config
}

func TestCorsWithUpstream(t *testing.T) {
	log.SetOutput(ioutil.Discard)

	config := testBuildCorsConfig()

	// launch fake upstream resource server
	_ = runTestUpstream(t, e2eCorsUpstreamListener, e2eCorsUpstreamURL)

	// launch fake oauth OIDC server
	_ = runTestAuth(t, e2eCorsOauthListener, "master")

	// launch keycloak-gatekeeper proxy
	_ = runTestGatekeeper(t, config)

	// ok now exercise the ensemble with a CORS-enabled request
	client := http.Client{}
	u, _ := url.Parse("http://" + e2eCorsProxyListener + e2eCorsUpstreamURL)
	h := make(http.Header, 1)
	h.Set("Content-Type", "application/json")
	h.Add("Origin", "myorigin.com")

	resp, err := client.Do(&http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	})
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	buf, erb := ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.Contains(t, string(buf), `"message": "test"`) // check this is our test resource
	if assert.NotEmpty(t, resp.Header) && assert.Contains(t, resp.Header, "Access-Control-Allow-Origin") {
		// check the returned upstream response after proxying contains CORS headers
		assert.Equal(t, []string{"*"}, resp.Header["Access-Control-Allow-Origin"])
	}
}

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
	"github.com/stretchr/testify/require"
)

const (
	e2eUpstreamsProxyListener = "127.0.0.1:23329"

	e2eUpstreamsOauthListener     = "127.0.0.1:13457"
	e2eUpstreamsUpstreamListener1 = "127.0.0.1:18512"
	e2eUpstreamsUpstreamListener2 = "127.0.0.1:8512"
	e2eUpstreamsUpstreamListener3 = "127.0.0.1:7512"

	e2eUpstreamsAppListener  = "127.0.0.1:3996"
	e2eUpstreamsAppURL       = "/ok"
	e2eUpstreamsUpstreamURL1 = "/api1"
	e2eUpstreamsUpstreamURL2 = "/api2"
	e2eUpstreamsUpstreamURL3 = "/api3"
)

func testBuildUpstreamsConfig() *Config {
	config := newDefaultConfig()
	config.Verbose = true
	config.EnableLogging = true
	config.DisableAllLogging = false

	config.Listen = e2eUpstreamsProxyListener
	config.DiscoveryURL = testDiscoveryURL(e2eUpstreamsOauthListener, "hod-test")

	config.Upstream = "http://" + e2eUpstreamsUpstreamListener3

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
			URL:           "/fake",
			Methods:       []string{"GET", "POST", "DELETE"},
			WhiteListed:   false,
			EnableCSRF:    false,
			Upstream:      "http://" + e2eUpstreamsUpstreamListener1 + e2eUpstreamsUpstreamURL1,
			StripBasePath: "/fake",
		},
	}
	config.Resources = append(config.Resources, &Resource{
		URL:         "/another-fake",
		Methods:     []string{"GET", "POST", "DELETE"},
		WhiteListed: false,
		EnableCSRF:  false,
		Upstream:    "http://" + e2eUpstreamsUpstreamListener2 + e2eUpstreamsUpstreamURL2,
	})
	config.Resources = append(config.Resources, &Resource{
		URL:         "/again-a-fake",
		Methods:     []string{"GET", "POST", "DELETE"},
		WhiteListed: false,
		EnableCSRF:  false,
	})
	config.EncryptionKey = secretForCookie
	return config
}

func TestUpstreams(t *testing.T) {
	log.SetOutput(ioutil.Discard)

	config := testBuildUpstreamsConfig()
	require.NoError(t, config.isValid())

	// launch fake oauth OIDC server
	err := runTestAuth(t, e2eUpstreamsOauthListener, "hod-test")
	require.NoError(t, err)

	// launch fake upstream resource serverS
	err = runTestUpstream(t, e2eUpstreamsUpstreamListener1, e2eUpstreamsUpstreamURL1, "mark1")
	require.NoError(t, err)

	err = runTestUpstream(t, e2eUpstreamsUpstreamListener2, e2eUpstreamsUpstreamURL2+"/another-fake", "mark2")
	require.NoError(t, err)

	err = runTestUpstream(t, e2eUpstreamsUpstreamListener3, e2eUpstreamsUpstreamURL3, "mark3")
	require.NoError(t, err)

	// launch fake app server where to land after authentication
	err = runTestApp(t, e2eUpstreamsAppListener, e2eUpstreamsAppURL)
	require.NoError(t, err)

	// launch keycloak-gatekeeper proxy
	err = runTestGatekeeper(t, config)
	require.NoError(t, err)

	// establish an authenticated session
	accessToken, cookies, err := runTestConnect(t, config, e2eUpstreamsAppListener, e2eUpstreamsAppURL)
	require.NoErrorf(t, err, "could not login: %v", err)
	require.NotEmpty(t, accessToken)

	// scenario 1: routing to different upstreams
	client := http.Client{}
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	h.Add("Accept", "application/json")

	// test upstream 1
	u, _ := url.Parse("http://" + e2eUpstreamsProxyListener + "/fake")
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}
	copyCookies(req, cookies)

	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(buf), "mark1")
	t.Logf(string(buf))

	// test upstream 2
	u, _ = url.Parse("http://" + e2eUpstreamsProxyListener + "/another-fake")
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}
	copyCookies(req, cookies)

	resp, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, err = ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(buf), "mark2")
	t.Logf(string(buf))

	// test upstream 3
	u, _ = url.Parse("http://" + e2eUpstreamsProxyListener + e2eUpstreamsUpstreamURL3)
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}
	copyCookies(req, cookies)

	resp, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, err = ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(buf), "mark3")
	t.Logf(string(buf))

	// this should route to {listener3}/api2 and returns 404
	u, _ = url.Parse("http://" + e2eUpstreamsProxyListener + e2eUpstreamsUpstreamURL2)
	req = &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}
	copyCookies(req, cookies)

	resp, err = client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// scenario 2: more basepath & path stripping
}

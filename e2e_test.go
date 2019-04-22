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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func runTestGatekeeper(t *testing.T, config *Config) error {
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
	t.Logf("test proxy gatekeeper: %s", config.Listen)
	return nil
}

func runTestUpstream(t *testing.T, listener, route string, markers ...string) error {
	go func() {
		upstreamHandler := func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"listener": "`+listener+`", "route": "`+route+`", "message": "test"`)
			for _, m := range markers {
				_, _ = io.WriteString(w, `,"marker": "`+m+`"`)
			}
			_, _ = io.WriteString(w, `}`)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Response-Header", "test")
		}
		http.HandleFunc(route, upstreamHandler)
		_ = http.ListenAndServe(listener, nil)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(listener, route))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(listener, route))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	t.Logf("test upstream server: %s%s", listener, route)
	return nil
}

func runTestApp(t *testing.T, listener, route string) error {
	go func() {
		mux := http.NewServeMux()
		appHandler := func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"message": "ok"}`)
			w.Header().Set("Content-Type", "application/json")
		}
		mux.HandleFunc(route, appHandler)
		_ = http.ListenAndServe(listener, mux)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(listener, route))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(listener, route))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	t.Logf("test app server: %s%s", listener, route)
	return nil
}

func testDiscoveryPath(realm string) string {
	return path.Join("/auth", "realms", realm, ".well-known", "openid-configuration")
}

func testDiscoveryURL(listener, realm string) string {
	return "http://" + listener + testDiscoveryPath(realm)
}

func runTestAuth(t *testing.T, listener, realm string) error {
	// a stub OIDC provider
	fake := newFakeAuthServer()
	fake.location, _ = url.Parse("http://" + listener)

	issuer := "http://" + listener + path.Join("/auth", "realms", realm)
	discoveryURL := testDiscoveryPath(realm)
	authorizeURL := path.Join("/auth", "realms", realm, "protocol", "openid-connect", "auth")
	// #nosec
	tokenURL := path.Join("/auth", "realms", realm, "protocol", "openid-connect", "token")
	jwksURL := path.Join("/auth", "realms", realm, "protocol", "openid-connect", "certs")

	go func() {
		mux := http.NewServeMux()
		configurationHandler := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"issuer": "`+issuer+`",
				"subject_types_supported":["public","pairwise"],
				"id_token_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512"],
				"userinfo_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512","none"],
				"authorization_endpoint":"http://`+listener+authorizeURL+`",
				"token_endpoint":"http://`+listener+tokenURL+`",
				"jwks_uri":"http://`+listener+jwksURL+`"
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
		mux.HandleFunc(discoveryURL, configurationHandler)
		mux.HandleFunc(authorizeURL, authorizeHandler)
		mux.HandleFunc(tokenURL, tokenHandler)
		mux.HandleFunc(jwksURL, keysHandler)
		_ = http.ListenAndServe(listener, mux)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(listener, jwksURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(listener, jwksURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	t.Logf("test auth server: %s [%s]", listener, realm)
	return nil
}

// runTestConnect exercises a connect scenario in which the client gets redirected to
// an OIDC authorize endpoint, then to the gatekeeper caller, and
// eventually to a custom endpoint specified in an initial cookie.
//
// NOTE: in this scenario, the "state" possibly passed by the initial query
// is no more carried on til the end of the endshake
//
// This scenario mimics a typical browser app running the authentication handshake
// in an iframe, the calling a custom URL to close the iframe after successful authentication.
//
// NOTE: for testing purposes, we use http transport and have to force our test client to
// forward the expected "request_uri" cookie set by the client.
func runTestConnect(t *testing.T, config *Config, listener, route string) (string, []*http.Cookie, error) {
	client := http.Client{
		Transport: controlledRedirect{
			CollectedCookies: make(map[string]*http.Cookie, 10),
		},
		CheckRedirect: onRedirect,
	}
	u, _ := url.Parse("http://" + config.Listen + "/oauth/authorize")
	v := u.Query()
	v.Set("state", "my_client_nonce") // NOTE: this state provided by the client is not currently carried on to the end (lost)
	u.RawQuery = v.Encode()

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: make(http.Header),
	}
	// add request_uri to specify last stop redirection (inner workings since PR #440)
	encoded := base64.StdEncoding.EncodeToString([]byte("http://" + listener + route))
	ck := &http.Cookie{
		Name:  "request_uri",
		Value: encoded,
		Path:  "/",
		// real life cookie gets Secure, SameSite
	}
	req.AddCookie(ck)

	// attempts to login
	resp, err := client.Do(req)
	if !assert.NoError(t, err) {
		return "", nil, err
	}

	// check that we get the final redirection to app correctly
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb := ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.JSONEq(t, `{"message": "ok"}`, string(buf))

	// returns all collected cookies during the handshake
	collector := client.Transport.(controlledRedirect)
	collected := make([]*http.Cookie, 0, 10)
	for _, ck := range collector.CollectedCookies {
		collected = append(collected, ck)
	}

	// assert kc-access cookie
	var (
		found       bool
		accessToken string
	)
	for _, ck := range collected {
		if ck.Name == config.CookieAccessName {
			accessToken = ck.Value
			found = true
			break
		}
	}
	assert.True(t, found)
	if t.Failed() {
		return "", nil, errors.New("failed to connect")
	}
	return accessToken, collected, nil
}

func getCookie(resp *http.Response, name string) (cookie *http.Cookie) {
	for _, ck := range resp.Cookies() {
		if ck.Name == name {
			cookie = ck
			break
		}
	}
	return
}

func copyCookies(req *http.Request, cookies []*http.Cookie) {
	ckMap := make(map[string]*http.Cookie, len(cookies))
	for _, ck := range cookies {
		if ck != nil {
			ckMap[ck.Name] = ck // dedupe
			// forward cookies obtained during authentication stage (mimicks browser)
			req.AddCookie(ckMap[ck.Name])
		}
	}
}

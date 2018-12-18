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
	"log"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/pressly/chi"
	"github.com/stretchr/testify/assert"
)

const (
	e2eCsrfUpstreamURL       = "/upstream"
	e2eCsrfUpstreamURL2      = "/upstream2"
	e2eCsrfUpstreamListener  = "127.0.0.1:12349"
	e2eCsrfProxyListener     = "127.0.0.1:54329"
	e2eCsrfOauthListener     = "127.0.0.1:33456"
	e2eCsrfAppListener       = "127.0.0.1:34569"
	e2eCsrfOauthURL          = "/auth/realms/hod-test/.well-known/openid-configuration"
	e2eCsrfOauthAuthorizeURL = "/auth/realms/hod-test/protocol/openid-connect/auth"
	// #nosec
	e2eCsrfOauthTokenURL = "/auth/realms/hod-test/protocol/openid-connect/token"
	e2eCsrfOauthJWKSURL  = "/auth/realms/hod-test/protocol/openid-connect/certs"
	e2eCsrfAppURL        = "/ok"
)

func runTestApp(t *testing.T) error {
	go func() {
		appHandler := func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"message": "ok"}`)
			w.Header().Set("Content-Type", "application/json")
		}
		http.HandleFunc(e2eCsrfAppURL, appHandler)
		_ = http.ListenAndServe(e2eCsrfAppListener, nil)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eCsrfAppListener, e2eCsrfAppURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eCsrfAppListener, e2eCsrfAppURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func runCsrfTestUpstream(t *testing.T) error {
	// a stub upstream API server
	go func() {
		getUpstream := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Response-Header", "test")
			_, _ = io.WriteString(w, `{"message": "test"}`)
		}

		postUpstream := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Response-Header", "test")
			_, _ = io.WriteString(w, `{"message": "posted"}`)
		}

		deleteUpstream := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Upstream-Response-Header", "test")
			_, _ = io.WriteString(w, `{"message": "deleted"}`)
		}

		upstream := chi.NewRouter()
		upstream.Route(e2eCsrfUpstreamURL, func(r chi.Router) {
			r.Get("/", getUpstream)
			r.Post("/", postUpstream)
			r.Delete("/", deleteUpstream)
		})
		upstream.Route(e2eCsrfUpstreamURL2, func(r chi.Router) {
			r.Get("/", getUpstream)
			r.Post("/", postUpstream)
			r.Delete("/", deleteUpstream)
		})

		_ = http.ListenAndServe(e2eCsrfUpstreamListener, upstream)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eCsrfUpstreamListener, e2eCsrfUpstreamURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eCsrfUpstreamListener, e2eCsrfUpstreamURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

func runCsrfTestAuth(t *testing.T) error {
	// a stub OIDC provider
	fake := newFakeAuthServer()
	fake.location, _ = url.Parse("http://" + e2eCsrfOauthListener)
	go func() {
		configurationHandler := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"issuer": "http://`+e2eCsrfOauthListener+`/auth/realms/hod-test",
				"subject_types_supported":["public","pairwise"],
				"id_token_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512"],
				"userinfo_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512","none"],
				"authorization_endpoint":"http://`+e2eCsrfOauthListener+e2eCsrfOauthAuthorizeURL+`",
				"token_endpoint":"http://`+e2eCsrfOauthListener+e2eCsrfOauthTokenURL+`",
				"jwks_uri":"http://`+e2eCsrfOauthListener+e2eCsrfOauthJWKSURL+`"
			}`)
		}

		authorizeHandler := func(w http.ResponseWriter, req *http.Request) {
			redirect := req.FormValue("redirect_uri")
			state := req.FormValue("state")
			code := "xyz"
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
		http.HandleFunc(e2eCsrfOauthURL, configurationHandler)
		http.HandleFunc(e2eCsrfOauthAuthorizeURL, authorizeHandler)
		http.HandleFunc(e2eCsrfOauthTokenURL, tokenHandler)
		http.HandleFunc(e2eCsrfOauthJWKSURL, keysHandler)
		_ = http.ListenAndServe(e2eCsrfOauthListener, nil)
	}()
	if !assert.True(t, checkListenOrBail("http://"+path.Join(e2eCsrfOauthListener, e2eCsrfOauthURL))) {
		err := fmt.Errorf("cannot connect to test http listener on: %s", "http://"+path.Join(e2eCsrfOauthListener, e2eCsrfOauthURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	return nil
}

// onRedirect forces the client to forward cookies on redirect, even though the URL is unsecure
func onRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 0 {
		for _, last := range via {
			for _, ck := range last.Cookies() {
				req.AddCookie(ck)
			}
		}
	}
	return nil
}

// controlledRedirect is a client RoundTripper to capture all cookies exchanged during the redirection process
// (assuming HttpOnly is not set for testing purpose)
type controlledRedirect struct {
	Transport        http.RoundTripper
	CollectedCookies map[string]*http.Cookie
}

func (c controlledRedirect) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	tr := c.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	if c.CollectedCookies == nil {
		c.CollectedCookies = make(map[string]*http.Cookie, 10)
	}
	for _, ck := range req.Cookies() {
		c.CollectedCookies[ck.Name] = ck
	}
	resp, err = tr.RoundTrip(req)
	if err != nil {
		return
	}
	for _, ck := range resp.Cookies() {
		req.AddCookie(ck)
		c.CollectedCookies[ck.Name] = ck
	}
	return
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
func runTestConnect(t *testing.T, config *Config) (string, []*http.Cookie, error) {
	client := http.Client{
		Transport: controlledRedirect{
			CollectedCookies: make(map[string]*http.Cookie, 10),
		},
		CheckRedirect: onRedirect,
	}
	u, _ := url.Parse("http://" + e2eCsrfProxyListener + "/oauth/authorize")
	v := u.Query()
	v.Set("state", "my_client_nonce") // NOTE: this state provided by the client is not currently carried on to the end (lost)
	u.RawQuery = v.Encode()

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: make(http.Header),
	}
	// add request_uri to specify last stop redirection (inner workings since PR #440)
	encoded := base64.StdEncoding.EncodeToString([]byte("http://" + e2eCsrfAppListener + e2eCsrfAppURL))
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

func getUpstreamTest(t *testing.T, config *Config, cookies []*http.Cookie, expectCSRFCookie bool) (string, []*http.Cookie, error) {
	// now exercise the ensemble with a CSRF-enabled request: this is the GET part to initialize
	// the CSRF state with a cookie
	client := http.Client{}

	u, _ := url.Parse("http://" + e2eCsrfProxyListener + e2eCsrfUpstreamURL)
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}

	copyCookies(req, cookies)
	resp, err := client.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb := ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.JSONEq(t, `{"message":"test"}`, string(buf)) // check this is our test resource being called

	if t.Failed() {
		return "", nil, errors.New("expected correct response body from upstream")
	}

	// now check CSRF security items
	if !assert.NotEmpty(t, resp.Header) {
		return "", nil, errors.New("expected some response headers")
	}

	if assert.Contains(t, resp.Header, "X-Upstream-Response-Header") { //
		// check the returned upstream response after proxying contains headers set upstream
		if !assert.Equal(t, []string{"test"}, resp.Header["X-Upstream-Response-Header"]) {
			return "", nil, errors.New("expected response header set by upstream")
		}
	}

	var csrfToken string
	if assert.Contains(t, resp.Header, config.CSRFHeader) { // we expect a CSRF header back
		csrfToken = resp.Header.Get(config.CSRFHeader)
		if !assert.NotEmpty(t, csrfToken) {
			return "", nil, errors.New("expected a non-empty CSRF token in response header")
		}
	} else {
		return "", nil, errors.New("expected a CSRF token in response header")
	}

	csrfCookie := getCookie(resp, config.CSRFCookieName)
	if expectCSRFCookie {
		if !assert.NotNil(t, csrfCookie) {
			return "", nil, errors.New("expected a CSRF cookie in response")
		}
	} else {
		if !assert.Nil(t, csrfCookie) {
			return "", nil, errors.New("did not expect a CSRF cookie in response")
		}

	}
	return csrfToken, append(cookies, csrfCookie), nil
}

func getTokenTest(t *testing.T, config *Config, cookies []*http.Cookie, expectCSRFCookie bool) (string, []*http.Cookie, error) {
	client := http.Client{}

	u, _ := url.Parse("http://" + e2eCsrfProxyListener + config.OAuthURI + "/" + tokenURL)
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}

	copyCookies(req, cookies)
	resp, err := client.Do(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb := ioutil.ReadAll(resp.Body)
	assert.NoError(t, erb)
	assert.NotEmpty(t, buf)

	if t.Failed() {
		return "", nil, errors.New("expected correct response body from upstream")
	}

	// now check CSRF security items
	if !assert.NotEmpty(t, resp.Header) {
		return "", nil, errors.New("expected some response headers")
	}

	var csrfToken string
	if assert.Contains(t, resp.Header, config.CSRFHeader) { // we expect a CSRF header back
		csrfToken = resp.Header.Get(config.CSRFHeader)
		if !assert.NotEmpty(t, csrfToken) {
			return "", nil, errors.New("expected a non-empty CSRF token in response header")
		}
	} else {
		return "", nil, errors.New("expected a CSRF token in response header")
	}

	csrfCookie := getCookie(resp, config.CSRFCookieName)
	if expectCSRFCookie {
		if !assert.NotNil(t, csrfCookie) {
			return "", nil, errors.New("expected a CSRF cookie in response")
		}
	} else {
		if !assert.Nil(t, csrfCookie) {
			return "", nil, errors.New("did not expect a CSRF cookie in response")
		}

	}
	return csrfToken, append(cookies, csrfCookie), nil
}

func postUpstreamTest(t *testing.T, config *Config, cookies []*http.Cookie, csrfToken string, expectedFailure bool) (string, []*http.Cookie, error) {
	client := http.Client{}

	u, _ := url.Parse("http://" + e2eCsrfProxyListener + e2eCsrfUpstreamURL)
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	h.Add(config.CSRFHeader, csrfToken)
	req := &http.Request{
		Method: "POST",
		URL:    u,
		Header: h,
	}

	// resend authentication and CSRF cookies (mimic browser)
	copyCookies(req, cookies)
	resp, err := client.Do(req)
	assert.NoError(t, err)

	var csrfNewToken string
	if !expectedFailure {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		buf, erb := ioutil.ReadAll(resp.Body)

		// checking response to POST
		assert.NoError(t, erb)
		assert.JSONEq(t, `{"message":"posted"}`, string(buf)) // check this is our test resource being called

		csrfNewToken = resp.Header.Get(config.CSRFHeader)
		assert.NotEmpty(t, csrfNewToken)
	} else {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		if resp.Header != nil {
			csrfNewToken = resp.Header.Get(config.CSRFHeader)
			assert.Empty(t, csrfNewToken)
		}
	}

	if t.Failed() {
		return "", nil, errors.New("error while checking POST CSRF scenario")
	}
	return csrfNewToken, append(cookies, getCookie(resp, config.CSRFCookieName)), nil
}

func postUpstreamWithAccessTokenTest(t *testing.T, config *Config, cookies []*http.Cookie, accessToken string) (string, []*http.Cookie, error) {
	client := http.Client{}

	u, _ := url.Parse("http://" + e2eCsrfProxyListener + e2eCsrfUpstreamURL)
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	h.Add("Authorization", "Bearer: "+accessToken)
	req := &http.Request{
		Method: "POST",
		URL:    u,
		Header: h,
	}

	// resend authentication and CSRF cookies (mimic browser)
	copyCookies(req, cookies)
	resp, err := client.Do(req)
	assert.NoError(t, err)

	var csrfNewToken string
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb := ioutil.ReadAll(resp.Body)

	// checking response to POST
	assert.NoError(t, erb)
	assert.JSONEq(t, `{"message":"posted"}`, string(buf)) // check this is our test resource being called

	csrfNewToken = resp.Header.Get(config.CSRFHeader)
	assert.Empty(t, csrfNewToken)

	if t.Failed() {
		return "", nil, errors.New("error while checking POST CSRF with Authorization header scenario")
	}
	return csrfNewToken, append(cookies, getCookie(resp, config.CSRFCookieName)), nil
}

func postUpstream2Test(t *testing.T, config *Config, cookies []*http.Cookie) (string, []*http.Cookie, error) {
	client := http.Client{}

	u, _ := url.Parse("http://" + e2eCsrfProxyListener + e2eCsrfUpstreamURL2)
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	req := &http.Request{
		Method: "POST",
		URL:    u,
		Header: h,
	}

	// resend authentication and CSRF cookies (mimic browser)
	copyCookies(req, cookies)
	resp, err := client.Do(req)
	assert.NoError(t, err)

	var csrfNewToken string
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf, erb := ioutil.ReadAll(resp.Body)

	// checking response to POST
	assert.NoError(t, erb)
	assert.JSONEq(t, `{"message":"posted"}`, string(buf)) // check this is our test resource being called

	csrfNewToken = resp.Header.Get(config.CSRFHeader)
	assert.Empty(t, csrfNewToken)

	if t.Failed() {
		return "", nil, errors.New("error while checking POST NO CSRF scenario")
	}
	return csrfNewToken, append(cookies, getCookie(resp, config.CSRFCookieName)), nil
}

func TestCSRF(t *testing.T) {
	log.SetOutput(ioutil.Discard)
	config := newDefaultConfig()
	config.Verbose = false
	config.DisableAllLogging = true
	config.EnableLogging = false

	config.Listen = e2eCsrfProxyListener
	config.DiscoveryURL = "http://" + e2eCsrfOauthListener + e2eCsrfOauthURL
	config.Upstream = "http://" + e2eCsrfUpstreamListener

	config.CorsOrigins = []string{"*"}
	config.EnableCSRF = true
	config.HTTPOnlyCookie = false // since we want to inspect the cookie for testing
	config.SecureCookie = false   // since we are testing over HTTP
	config.AccessTokenDuration = 30 * time.Minute
	config.EnableEncryptedToken = false
	config.EnableSessionCookies = true
	config.ClientID = fakeClientID
	config.ClientSecret = fakeSecret
	config.Resources = []*Resource{
		{
			URL:         e2eCsrfUpstreamURL2,
			Methods:     []string{"GET", "POST", "DELETE"},
			WhiteListed: false,
			EnableCSRF:  false,
		},
	}
	assert.Error(t, config.isValid())

	config.EncryptionKey = "01234567890123456789012345678901"
	assert.Error(t, config.isValid())

	config.Resources = append(config.Resources, &Resource{
		URL:         e2eCsrfUpstreamURL,
		Methods:     []string{"GET", "POST", "DELETE"},
		WhiteListed: false,
		EnableCSRF:  true,
	})
	assert.NoError(t, config.isValid())

	// launch fake upstream resource server
	err := runCsrfTestUpstream(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch fake app server where to land after authentication
	err = runTestApp(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch fake oauth OIDC server
	err = runCsrfTestAuth(t)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// launch keycloak-gatekeeper proxy
	err = runTestGatekeeper(t, config)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// establish an authenticated session
	accessToken, cookies, err := runTestConnect(t, config)
	if !assert.NoError(t, err) {
		t.Logf("could not login: %v", err)
		t.FailNow()
	}
	var found bool
	for _, ck := range cookies {
		if ck.Name == config.CSRFCookieName {
			found = true
			break
		}
	}
	assert.True(t, found)

	csrfToken, newCookies, err := getUpstreamTest(t, config, cookies, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on GET upstream test: %v", err)
		t.FailNow()
	}

	// Scenario 1: call protected resource, with CSRF state ready
	//   - calls upstream with a properly authenticated POST, adding the expected CSRF header
	csrfNewToken, newCookies, err := postUpstreamTest(t, config, newCookies, csrfToken, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 1: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 1 passed")

	// Scenario 2: POST again with the newly returned header
	//   - calls upstream with a properly authenticated POST, adding the init CSRF header, with latest received CSRF header
	_, newCookies, err = postUpstreamTest(t, config, newCookies, csrfNewToken, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 1: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 2 passed")

	// Scenario 3: replaying an older valid token on POST, within the same session
	// This illustrates the generation of one-time in-the-clear header token remaining valid for the session
	// (allows multiple tabs usage).
	//
	//   - calls upstream with a properly authenticated POST, adding the init CSRF header, with some older CSRF header
	//     retrieved during the session
	_, newCookies, err = postUpstreamTest(t, config, newCookies, csrfToken, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 3: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 3 passed")

	// Scenario 4: POST with an invalid token
	_, newCookies, err = postUpstreamTest(t, config, newCookies, "fake-token", true)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 4: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 4 passed")

	// Scenario 5: POST without CSRF token header, but with a Authorization Bearer header
	_, newCookies, err = postUpstreamWithAccessTokenTest(t, config, newCookies, accessToken)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 5: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 5 passed")

	// Scenario 6: POST without CSRF token header, on resource with disabled CSRF
	_, newCookies, err = postUpstream2Test(t, config, newCookies)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 6: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 6 passed")

	// Scenario 7: check if CSRF state changes with new GET
	//   - cookie is already there and (normally) not expired: not sent back
	csrfNewToken, _, err = getUpstreamTest(t, config, newCookies, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on GET upstream test scenario 7: %v", err)
		t.FailNow()
	}

	_, _, err = postUpstreamTest(t, config, newCookies, csrfNewToken, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on POST upstream scenario 7: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 7 passed")

	// Scenario 8: admin endpoints (e.g. /oauth/token) may yield a CSRF token in header
	// (use-case: init CSRF state before calling APIs, when first call is a POST/PUT/DELETE...)
	_, _, err = getTokenTest(t, config, newCookies, false)
	if !assert.NoError(t, err) {
		t.Logf("CSRF test failed on GET upstream test scenario 8: %v", err)
		t.FailNow()
	}
	t.Logf("CSRF test on POST upstream scenario 8 passed")
}

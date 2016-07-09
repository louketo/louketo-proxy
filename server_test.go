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
	"bufio"
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	fakeClientID = "test"
	fakeSecret   = fakeClientID

	fakeAdminRoleURL       = "/admin"
	fakeTestRoleURL        = "/test_role"
	fakeTestAdminRolesURL  = "/test_admin_roles"
	fakeAuthAllURL         = "/auth_all"
	fakeTestWhitelistedURL = fakeAuthAllURL + "/white_listed"
	fakeTestListenOrdered  = fakeAuthAllURL + "/bad_order"

	fakeAdminRole = "role:admin"
	fakeTestRole  = "role:test"
)

func newFakeKeycloakConfig() *Config {
	return &Config{
		DiscoveryURL:          "127.0.0.1:8080",
		ClientID:              fakeClientID,
		ClientSecret:          fakeSecret,
		EncryptionKey:         "AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j",
		SkipTokenVerification: true,
		Scopes:                []string{},
		EnableRefreshTokens:   false,
		SecureCookie:          false,
		CookieAccessName:      "kc-access",
		CookieRefreshName:     "kc-state",
		Resources: []*Resource{
			{
				URL:     fakeAdminRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole},
			},
			{
				URL:     fakeTestRoleURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeTestRole},
			},
			{
				URL:     fakeTestAdminRolesURL,
				Methods: []string{"GET"},
				Roles:   []string{fakeAdminRole, fakeTestRole},
			},
			{
				URL:         fakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     []string{},
				Roles:       []string{},
			},
			{
				URL:     fakeAuthAllURL,
				Methods: []string{"ANY"},
				Roles:   []string{},
			},
			{
				URL:         fakeTestWhitelistedURL,
				WhiteListed: true,
				Methods:     []string{},
				Roles:       []string{},
			},
		},
		CrossOrigin: CORS{},
	}
}

func newTestProxyService(config *Config) (*oauthProxy, *fakeOAuthServer, string) {
	log.SetOutput(ioutil.Discard)
	// step: create a fake oauth server
	auth := newFakeOAuthServer()
	// step: use the default config if required
	if config == nil {
		config = newFakeKeycloakConfig()
	}

	// step: set the config
	config.LogRequests = true
	config.SkipTokenVerification = false
	config.DiscoveryURL = auth.getLocation()
	config.Verbose = false

	// step: create a proxy
	proxy, err := newProxy(config)
	if err != nil {
		panic("failed to create proxy service, error: " + err.Error())
	}

	// step: create an fake upstream endpoint
	proxy.upstream = new(fakeReverseProxy)
	service := httptest.NewServer(proxy.router)
	config.RedirectionURL = service.URL

	// step: we need to update the client config
	proxy.client, proxy.provider, err = createOpenIDClient(config)
	if err != nil {
		panic("failed to recreate the openid client, error: " + err.Error())
	}

	return proxy, auth, service.URL
}

func newFakeKeycloakProxyWithResources(t *testing.T, resources []*Resource) *oauthProxy {
	p, _, _ := newTestProxyService(nil)
	p.config.Resources = resources
	p.endpoint = &url.URL{
		Host: "127.0.0.1",
	}

	return p
}

func TestNewKeycloakProxy(t *testing.T) {
	proxy, err := newProxy(newFakeKeycloakConfig())
	assert.NoError(t, err)
	assert.NotNil(t, proxy)
	assert.NotNil(t, proxy.config)
	assert.NotNil(t, proxy.router)
	assert.NotNil(t, proxy.endpoint)
}

func TestRedirectToAuthorization(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	p.config.SkipTokenVerification = false
	p.redirectToAuthorization(context)
	assert.Equal(t, http.StatusTemporaryRedirect, context.Writer.Status())
}

func TestRedirectToAuthorizationSkipToken(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	p.config.SkipTokenVerification = true
	p.redirectToAuthorization(context)
	assert.Equal(t, http.StatusForbidden, context.Writer.Status())
}

func TestRedirectToAuthorizationUnauthorized(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)
	p.config.SkipTokenVerification = false
	p.config.NoRedirects = true

	p.redirectToAuthorization(context)
	assert.Equal(t, http.StatusUnauthorized, context.Writer.Status())
}

func TestCreateReverseProxy(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)
	err := createReverseProxy(proxy.config, proxy)
	assert.NoError(t, err)
	assert.NotNil(t, proxy.router)
}

func TestCreateForwardProxy(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)
	err := createForwardingProxy(proxy.config, proxy)
	assert.NoError(t, err)
	assert.NotNil(t, proxy.router)
}

func TestRedirectURL(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	if p.redirectToURL("http://127.0.0.1", context); context.Writer.Status() != http.StatusTemporaryRedirect {
		t.Errorf("we should have recieved a redirect")
	}

	if !context.IsAborted() {
		t.Errorf("the context should have been aborted")
	}
}

func TestAccessForbidden(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	p.config.SkipTokenVerification = false
	if p.accessForbidden(context); context.Writer.Status() != http.StatusForbidden {
		t.Errorf("we should have recieved a forbidden access")
	}

	p.config.SkipTokenVerification = true
	if p.accessForbidden(context); context.Writer.Status() != http.StatusForbidden {
		t.Errorf("we should have recieved a forbidden access")
	}
}

func newFakeResponse() *fakeResponse {
	return &fakeResponse{
		status:  http.StatusOK,
		headers: make(http.Header, 0),
	}
}

func newFakeGinContext(method, uri string) *gin.Context {
	return &gin.Context{
		Request: &http.Request{
			Method:     method,
			Host:       "127.0.0.1",
			RequestURI: uri,
			URL: &url.URL{
				Scheme: "http",
				Host:   "127.0.0.1",
				Path:   uri,
			},
			Header:     make(http.Header, 0),
			RemoteAddr: "127.0.0.1:8989",
		},
		Writer: newFakeResponse(),
	}
}

func newFakeGinContextWithCookies(method, url string, cookies []*http.Cookie) *gin.Context {
	cx := newFakeGinContext(method, url)
	for _, x := range cookies {
		cx.Request.AddCookie(x)
	}

	return cx
}

func newFakeJWTToken(t *testing.T, claims jose.Claims) *jose.JWT {
	token, err := jose.NewJWT(
		jose.JOSEHeader{"alg": "RS256"}, claims,
	)
	if err != nil {
		t.Fatalf("failed to create the jwt token, error: %s", err)
	}

	return &token
}

type fakeReverseProxy struct{}

func (r fakeReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {}

type fakeResponse struct {
	size    int
	status  int
	headers http.Header
	body    bytes.Buffer
	written bool
}

func (r *fakeResponse) Flush()              {}
func (r *fakeResponse) Written() bool       { return r.written }
func (r *fakeResponse) WriteHeaderNow()     {}
func (r *fakeResponse) Size() int           { return r.size }
func (r *fakeResponse) Status() int         { return r.status }
func (r *fakeResponse) Header() http.Header { return r.headers }
func (r *fakeResponse) WriteHeader(code int) {
	r.status = code
	r.written = true
}
func (r *fakeResponse) Write(content []byte) (int, error)            { return len(content), nil }
func (r *fakeResponse) WriteString(s string) (int, error)            { return len(s), nil }
func (r *fakeResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }
func (r *fakeResponse) CloseNotify() <-chan bool                     { return make(chan bool, 0) }

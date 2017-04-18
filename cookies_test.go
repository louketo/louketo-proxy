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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCookieDomainHostHeader(t *testing.T) {
	svc := newTestService()
	resp, err := makeTestCodeFlowLogin(svc + "/admin")
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "kc-access" {
			cookie = c
		}
	}
	assert.NotNil(t, cookie)
	assert.Equal(t, cookie.Domain, "127.0.0.1")
}

func TestCookieDomain(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.config.CookieDomain = "domain.com"
	resp, err := makeTestCodeFlowLogin(svc + "/admin")
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "kc-access" {
			cookie = c
		}
	}
	assert.NotNil(t, cookie)
	assert.Equal(t, cookie.Domain, "domain.com")
}

func TestDropCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.1",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	p.config.SecureCookie = false
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.1",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	p.config.SecureCookie = true
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)
	assert.NotEqual(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.2; HttpOnly; Secure",
		"we have not set the cookie, headers: %v", resp.Header())

	p.config.CookieDomain = "test.com"
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)
	p.config.SecureCookie = false
	assert.NotEqual(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=test.com;",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestDropRefreshCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.dropRefreshTokenCookie(req, resp, "test", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"kc-state=test; Path=/; Domain=127.0.0.1",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestHTTPOnlyCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.1",
		"we have not set the cookie, headers: %v", resp.Header())

	req = newFakeHTTPRequest("GET", "/admin")
	resp = httptest.NewRecorder()
	p.config.HTTPOnlyCookie = true
	p.dropCookie(resp, req.Host, "test-cookie", "test-value", 0)

	assert.Equal(t, resp.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.1; HttpOnly",
		"we have not set the cookie, headers: %v", resp.Header())
}

func TestClearAccessTokenCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.clearAccessTokenCookie(req, resp)
	assert.Contains(t, resp.Header().Get("Set-Cookie"),
		"kc-access=; Path=/; Domain=127.0.0.1; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearRefreshAccessTokenCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.clearRefreshTokenCookie(req, resp)
	assert.Contains(t, resp.Header().Get("Set-Cookie"),
		"kc-state=; Path=/; Domain=127.0.0.1; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

func TestClearAllCookies(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	req := newFakeHTTPRequest("GET", "/admin")
	resp := httptest.NewRecorder()
	p.clearAllCookies(req, resp)
	assert.Contains(t, resp.Header().Get("Set-Cookie"),
		"kc-access=; Path=/; Domain=127.0.0.1; Expires=",
		"we have not cleared the, headers: %v", resp.Header())
}

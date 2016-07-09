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
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/stretchr/testify/assert"
)

func TestExpirationHandler(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)

	cases := []struct {
		Token    *jose.JWT
		HTTPCode int
	}{
		{
			HTTPCode: http.StatusUnauthorized,
		},
		{
			Token: newFakeJWTToken(t, jose.Claims{
				"exp": float64(time.Now().Add(-24 * time.Hour).Unix()),
			}),
			HTTPCode: http.StatusUnauthorized,
		},
		{
			Token: newFakeJWTToken(t, jose.Claims{
				"exp":                float64(time.Now().Add(10 * time.Hour).Unix()),
				"aud":                "test",
				"iss":                "https://keycloak.example.com/auth/realms/commons",
				"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
				"email":              "gambol99@gmail.com",
				"name":               "Rohith Jayawardene",
				"preferred_username": "rjayawardene",
			}),
			HTTPCode: http.StatusOK,
		},
		{
			Token: newFakeJWTToken(t, jose.Claims{
				"exp":                float64(time.Now().Add(-24 * time.Hour).Unix()),
				"aud":                "test",
				"iss":                "https://keycloak.example.com/auth/realms/commons",
				"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
				"email":              "gambol99@gmail.com",
				"name":               "Rohith Jayawardene",
				"preferred_username": "rjayawardene",
			}),
			HTTPCode: http.StatusUnauthorized,
		},
	}

	for i, c := range cases {
		// step: inject a resource
		cx := newFakeGinContext("GET", "/oauth/expiration")
		// step: add the token is there is one
		if c.Token != nil {
			cx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token.Encode()))
		}
		// step: if closure so we need to get the handler each time
		proxy.expirationHandler(cx)
		// step: check the content result
		assert.Equal(t, c.HTTPCode, cx.Writer.Status(), "test case %d should have recieved: %d, but got %d", i,
			c.HTTPCode, cx.Writer.Status())
	}
}

func TestLoginHandler(t *testing.T) {
	_, _, u := newTestProxyService(nil)

	cs := []struct {
		Username     string
		Password     string
		ExpectedCode int
	}{
		{
			Username:     "",
			Password:     "",
			ExpectedCode: http.StatusBadRequest,
		},
		{
			Username:     "test",
			Password:     "",
			ExpectedCode: http.StatusBadRequest,
		},
		{
			Username:     "",
			Password:     "test",
			ExpectedCode: http.StatusBadRequest,
		},
		{
			Username:     "test",
			Password:     "test",
			ExpectedCode: http.StatusOK,
		},
	}

	for i, x := range cs {
		u := u + oauthURL + loginURL
		values := url.Values{}
		if x.Username != "" {
			values.Add("username", x.Username)
		}
		if x.Password != "" {
			values.Add("password", x.Password)
		}

		resp, err := http.PostForm(u, values)
		if err != nil {
			t.Errorf("case %d, unable to make requets, error: %s", i, err)
			continue
		}
		assert.Equal(t, x.ExpectedCode, resp.StatusCode, "case %d, expect: %v, got: %d",
			i, x.ExpectedCode, resp.StatusCode)
	}
}

func TestTokenHandler(t *testing.T) {
	token := newFakeAccessToken()
	_, _, u := newTestProxyService(nil)
	url := u + oauthURL + tokenURL

	// step: get a request
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token.Encode())
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Errorf("failed to make request, error: %s", err)
		t.FailNow()
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, _ = http.NewRequest("GET", url, nil)
	resp, err = http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Errorf("failed to make request, error: %s", err)
		t.FailNow()
	}
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAuthorizationURL(t *testing.T) {
	_, _, u := newTestProxyService(nil)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("no redirect")
		},
	}
	cs := []struct {
		URL          string
		ExpectedURL  string
		ExpectedCode int
	}{
		{
			URL:          "/",
			ExpectedCode: http.StatusNotFound,
		},
		{
			URL:          "/admin",
			ExpectedURL:  "/oauth/authorize?state=L2FkbWlu",
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URL:          "/admin/test",
			ExpectedURL:  "/oauth/authorize?state=L2FkbWluL3Rlc3Q=",
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URL:          "/admin/../",
			ExpectedURL:  "/oauth/authorize?state=L2FkbWluLy4uLw==",
			ExpectedCode: http.StatusTemporaryRedirect,
		},
		{
			URL:          "/admin?test=yes&test1=test",
			ExpectedURL:  "/oauth/authorize?state=L2FkbWluP3Rlc3Q9eWVzJnRlc3QxPXRlc3Q=",
			ExpectedCode: http.StatusTemporaryRedirect,
		},
	}
	for i, x := range cs {
		resp, _ := client.Get(u + x.URL)
		assert.Equal(t, x.ExpectedCode, resp.StatusCode, "case %d, expect: %v, got: %s", i, x.ExpectedCode, resp.StatusCode)
		assert.Equal(t, x.ExpectedURL, resp.Header.Get("Location"), "case %d, expect: %v, got: %s", i, x.ExpectedURL, resp.Header.Get("Location"))
	}
}

func TestCallbackURL(t *testing.T) {
	_, _, u := newTestProxyService(nil)

	cs := []struct {
		URL         string
		ExpectedURL string
	}{
		{
			URL:         "/oauth/authorize?state=L2FkbWlu",
			ExpectedURL: "/admin",
		},
		{
			URL:         "/oauth/authorize",
			ExpectedURL: "/",
		},
		{
			URL:         "/oauth/authorize?state=L2FkbWluL3Rlc3QxP3Rlc3QxJmhlbGxv",
			ExpectedURL: "/admin/test1?test1&hello",
		},
	}
	for i, x := range cs {
		// step: call the authorization endpoint
		req, err := http.NewRequest("GET", u+x.URL, nil)
		if err != nil {
			continue
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if !assert.NoError(t, err, "case %d, should not have failed", i) {
			continue
		}
		openIDURL := resp.Header.Get("Location")
		if !assert.NotEmpty(t, openIDURL, "case %d, the open id redirection url is empty", i) {
			continue
		}
		req, _ = http.NewRequest("GET", openIDURL, nil)
		resp, err = http.DefaultTransport.RoundTrip(req)
		if !assert.NoError(t, err, "case %d, should not have failed calling the opend id url", i) {
			continue
		}
		callbackURL := resp.Header.Get("Location")
		if !assert.NotEmpty(t, callbackURL, "case %d, should have recieved a callback url", i) {
			continue
		}
		// step: call the callback url
		req, _ = http.NewRequest("GET", callbackURL, nil)
		resp, err = http.DefaultTransport.RoundTrip(req)
		if !assert.NoError(t, err, "case %d, unable to call the callback url", i) {
			continue
		}
		// step: check the callback location is as expected
		assert.Contains(t, resp.Header.Get("Location"), x.ExpectedURL)
	}
}

func TestHealthHandler(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	context := newFakeGinContext("GET", healthURL)
	p.healthHandler(context)
	assert.Equal(t, http.StatusOK, context.Writer.Status())
	assert.NotEmpty(t, context.Writer.Header().Get(versionHeader))
	assert.Equal(t, version, context.Writer.Header().Get(versionHeader))
}

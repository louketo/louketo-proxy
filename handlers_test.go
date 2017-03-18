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
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-resty/resty"
	"github.com/stretchr/testify/assert"
)

func TestExpirationHandler(t *testing.T) {
	_, idp, svc := newTestProxyService(nil)
	cases := []struct {
		ExpireIn time.Duration
		Expects  int
	}{
		{
			Expects: http.StatusUnauthorized,
		},
		{
			ExpireIn: time.Duration(-24 * time.Hour),
			Expects:  http.StatusUnauthorized,
		},
		{
			ExpireIn: time.Duration(14 * time.Hour),
			Expects:  http.StatusOK,
		},
	}

	for i, c := range cases {
		token := newTestToken(idp.getLocation())
		token.setExpiration(time.Now().Add(c.ExpireIn))
		// sign the token
		signed, _ := idp.signToken(token.claims)
		// make the request
		resp, err := resty.New().SetAuthToken(signed.Encode()).R().Get(svc + oauthURL + expiredURL)
		if !assert.NoError(t, err, "case %d unable to make the request, error: %s", i, err) {
			continue
		}
		assert.Equal(t, c.Expects, resp.StatusCode(), "case %d, expects: %d but got: %d", i, c.Expects, resp.StatusCode())
	}
}

func TestLoginHandlerDisabled(t *testing.T) {
	config := newFakeKeycloakConfig()
	config.EnableLoginHandler = false

	_, _, url := newTestProxyService(config)
	resp, err := resty.DefaultClient.R().Post(url + "/oauth/login")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode())
}

func TestLoginHandlerNotDisabled(t *testing.T) {
	config := newFakeKeycloakConfig()
	config.EnableLoginHandler = true
	_, _, url := newTestProxyService(config)
	resp, err := http.Post(url+"/oauth/login", "", nil)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
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
		{
			Username:     "test",
			Password:     "notmypassword",
			ExpectedCode: http.StatusUnauthorized,
		},
	}

	for i, x := range cs {
		uri := u + oauthURL + loginURL
		values := url.Values{}
		if x.Username != "" {
			values.Add("username", x.Username)
		}
		if x.Password != "" {
			values.Add("password", x.Password)
		}

		resp, err := http.PostForm(uri, values)
		if err != nil {
			t.Errorf("case %d, unable to make requets, error: %s", i, err)
			continue
		}
		assert.Equal(t, x.ExpectedCode, resp.StatusCode, "case %d, expect: %v, got: %d",
			i, x.ExpectedCode, resp.StatusCode)
	}
}

func TestLogoutHandlerBadRequest(t *testing.T) {
	_, _, u := newTestProxyService(nil)

	res, err := http.Get(u + oauthURL + logoutURL)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, res.StatusCode, http.StatusBadRequest)
}

func TestLogoutHandlerBadToken(t *testing.T) {
	u := newTestService()
	req, err := http.NewRequest("GET", u+oauthURL+logoutURL, nil)
	assert.NoError(t, err)
	req.Header.Add("kc-access", "this.is.a.bad.token")
	res, err := http.DefaultTransport.RoundTrip(req)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestLogoutHandlerGood(t *testing.T) {
	u := newTestService()
	// step: first we login and get a token
	token, err := makeTestOauthLogin(u + "/admin")
	if !assert.NoError(t, err) {
		t.Errorf("failed to perform oauth login, reason: %s", err)
		t.Fail()
	}

	// step: attempt to logout
	res, err := resty.DefaultClient.R().
		SetAuthToken(token).
		Get(u + oauthURL + logoutURL)
	if !assert.NoError(t, err) {
		t.Fail()
	}
	assert.Equal(t, http.StatusOK, res.StatusCode())
}

func TestTokenHandler(t *testing.T) {
	token := newFakeAccessToken(nil, 0)
	svc := newTestService()
	cs := []struct {
		Token    string
		Cookie   string
		Expected int
	}{
		{
			Token:    token.Encode(),
			Expected: http.StatusOK,
		},
		{
			Expected: http.StatusBadRequest,
		},
		{
			Token:    "niothing",
			Expected: http.StatusBadRequest,
		},
		{
			Cookie:   token.Encode(),
			Expected: http.StatusOK,
		},
	}
	requrl := svc + oauthURL + tokenURL
	for _, c := range cs {
		client := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
		if c.Token != "" {
			client.SetAuthToken(c.Token)
		}
		if c.Cookie != "" {
			client.SetCookie(&http.Cookie{
				Name:  "kc-access",
				Path:  "/",
				Value: c.Cookie,
			})
		}
		resp, err := client.R().Get(requrl)
		assert.NoError(t, err)
		assert.Equal(t, c.Expected, resp.StatusCode())
	}
}

func TestNoRedirect(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.config.NoRedirects = true

	req, _ := http.NewRequest("GET", svc+"/admin", nil)
	resp, err := http.DefaultTransport.RoundTrip(req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	p.config.NoRedirects = false
	req, _ = http.NewRequest("GET", svc+"/admin", nil)
	resp, err = http.DefaultTransport.RoundTrip(req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
}

func TestAuthorizationURL(t *testing.T) {
	_, _, u := newTestProxyService(nil)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("no redirect")
		},
	}
	cs := []struct {
		URL          string
		ExpectedURL  string
		ExpectedCode int
	}{
		{
			URL:          "/",
			ExpectedCode: http.StatusOK,
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
			URL:          "/help/../admin",
			ExpectedURL:  "/oauth/authorize?state=L2FkbWlu",
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
		if !assert.NotEmpty(t, callbackURL, "case %d, should have received a callback url", i) {
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
	svc := newTestService()
	resp, err := resty.DefaultClient.R().Get(svc + oauthURL + healthURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.Equal(t, version, resp.Header().Get(versionHeader))
}

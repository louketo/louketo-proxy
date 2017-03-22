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
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/go-resty/resty"
	"github.com/stretchr/testify/assert"
)

type fakeRequest struct {
	URI       string
	Method    string
	Redirects bool
	HasToken  bool
	NotSigned bool
	Expires   time.Duration
	Roles     []string
	Expects   int
}

func makeFakesRequests(t *testing.T, reqs []fakeRequest, cfg *Config) {
	cfg.SkipTokenVerification = false
	px, idp, svc := newTestProxyService(cfg)
	for i, c := range reqs {
		px.config.NoRedirects = !c.Redirects
		// step: make the client
		hc := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
		if c.HasToken {
			token := newTestToken(idp.getLocation())
			if len(c.Roles) > 0 {
				token.setRealmsRoles(c.Roles)
			}
			if c.Expires > 0 {
				token.setExpiration(time.Now().Add(c.Expires))
			}
			if !c.NotSigned {
				signed, err := idp.signToken(token.claims)
				if !assert.NoError(t, err, "case %d, unable to sign the token, error: %s", i, err) {
					continue
				}
				hc.SetAuthToken(signed.Encode())
			} else {
				jwt := token.getToken()
				hc.SetAuthToken(jwt.Encode())
			}
		}
		// step: make the request
		resp, err := hc.R().Execute(c.Method, svc+c.URI)
		if err != nil {
			if !strings.Contains(err.Error(), "Auto redirect is disable") {
				assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err)
				continue
			}
		}
		// step: check against the expected
		assert.Equal(t, c.Expects, resp.StatusCode(), "case %d, uri: %s,  expected: %d, got: %d",
			i, c.URI, c.Expects, resp.StatusCode())
	}
}

func TestOauthRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	requests := []fakeRequest{
		{
			URI:       "/oauth/authorize",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{
			URI:       "/oauth/callback",
			Redirects: true,
			Expects:   http.StatusBadRequest,
		},
		{
			URI:       "/oauth/health",
			Redirects: true,
			Expects:   http.StatusOK,
		},
	}
	makeFakesRequests(t, requests, cfg)
}

func TestStrangeAdminRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
			Roles:   []string{fakeAdminRole},
		},
	}
	requests := []fakeRequest{
		{ // check for escaping
			URI:       "//admin%2Ftest",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{ // check for escaping
			URI:       "/admin%2Ftest",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{ // check for prefix slashs
			URI:       "//admin/test",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{ // check for prefix slashs
			URI:       "/admin//test",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{ // check for prefix slashs
			URI:       "/admin//test",
			Redirects: false,
			HasToken:  true,
			Expects:   http.StatusForbidden,
		},
		{ // check for dodgy url
			URI:       "//admin/../admin/test",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{ // check for it works
			URI:      "//admin/test",
			HasToken: true,
			Roles:    []string{fakeAdminRole},
			Expects:  http.StatusOK,
		},
		{ // check for it works
			URI:      "//admin//test",
			HasToken: true,
			Roles:    []string{fakeAdminRole},
			Expects:  http.StatusOK,
		},
		{
			URI:       "/help/../admin/test/21",
			Redirects: false,
			Expects:   http.StatusUnauthorized,
		},
	}
	makeFakesRequests(t, requests, cfg)
}

func TestWhiteListedRequests(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:         "/whitelist",
			WhiteListed: true,
			Methods:     []string{"GET"},
			Roles:       []string{},
		},
		{
			URL:     "/",
			Methods: []string{"ANY"},
			Roles:   []string{fakeTestRole},
		},
		{
			URL:         "/whitelisted",
			WhiteListed: true,
			Methods:     []string{"ANY"},
			Roles:       []string{fakeTestRole},
		},
	}
	requests := []fakeRequest{
		{ // check whitelisted is passed
			URI:     "/whitelist",
			Expects: http.StatusOK,
		},
		{ // check whitelisted is passed
			URI:     "/whitelist/test",
			Expects: http.StatusOK,
		},
		{
			URI:     "/",
			Expects: http.StatusUnauthorized,
		},
	}
	makeFakesRequests(t, requests, cfg)
}

func TestRolePermissionsMiddleware(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
			Roles:   []string{fakeAdminRole},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{fakeTestRole},
		},
		{
			URL:     "/test_admin_role",
			Methods: []string{"GET"},
			Roles:   []string{fakeAdminRole, fakeTestRole},
		},
		{
			URL:         "/whitelist",
			WhiteListed: true,
			Methods:     []string{"GET"},
			Roles:       []string{},
		},
		{
			URL:     "/",
			Methods: []string{"ANY"},
			Roles:   []string{fakeTestRole},
		},
	}
	// test cases
	requests := []fakeRequest{
		{
			URI:     "/",
			Expects: http.StatusUnauthorized,
		},
		{ // check for redirect
			URI:       "/",
			Redirects: true,
			Expects:   http.StatusTemporaryRedirect,
		},
		{ // check with a token
			URI:       "/",
			Redirects: false,
			HasToken:  true,
			Expects:   http.StatusForbidden,
		},
		{ // check with a token and wrong roles
			URI:       "/",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{"one", "two"},
			Expects:   http.StatusForbidden,
		},
		{ // token, wrong roles
			URI:       "/test",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{"bad_role"},
			Expects:   http.StatusForbidden,
		},
		{ // token, wrong roles, no 'get' method
			URI:       "/test",
			Method:    http.MethodPost,
			Redirects: false,
			HasToken:  true,
			Roles:     []string{"bad_role"},
			Expects:   http.StatusOK,
		},
		{ // check with correct token
			URI:       "/test",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeTestRole},
			Expects:   http.StatusOK,
		},
		{ // check with correct token
			URI:       "/",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeTestRole},
			Expects:   http.StatusOK,
		},
		{ // check with correct token, not signed
			URI:       "/",
			Redirects: false,
			HasToken:  true,
			NotSigned: true,
			Roles:     []string{fakeTestRole},
			Expects:   http.StatusForbidden,
		},
		{ // check with correct token, signed
			URI:       "/admin/page",
			Method:    http.MethodPost,
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeTestRole},
			Expects:   http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:       "/admin/page",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeTestRole},
			Expects:   http.StatusForbidden,
		},
		{ // check with correct token, signed, wrong roles
			URI:       "/admin/page",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeTestRole, fakeAdminRole},
			Expects:   http.StatusOK,
		},
		{ // strange url
			URI:       "/admin/..//admin/page",
			Redirects: false,
			Expects:   http.StatusUnauthorized,
		},
		{ // strange url, token
			URI:       "/admin/../admin",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{"hehe"},
			Expects:   http.StatusForbidden,
		},
		{ // strange url, token
			URI:       "/test/../admin",
			Redirects: false,
			HasToken:  true,
			Expects:   http.StatusForbidden,
		},
		{ // strange url, token, role
			URI:       "/test/../admin",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeAdminRole},
			Expects:   http.StatusOK,
		},
		{ // strange url, token, wrong roles
			URI:       "/test/../admin",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeAdminRole},
			Expects:   http.StatusOK,
		},
		{ // strange url, token, wrong roles
			URI:       "/test/../admin",
			Redirects: false,
			HasToken:  true,
			Roles:     []string{fakeTestRole},
			Expects:   http.StatusForbidden,
		},
	}
	makeFakesRequests(t, requests, cfg)
}

func TestCrossSiteHandler(t *testing.T) {
	cases := []struct {
		Cors    Cors
		Headers map[string]string
	}{
		{
			Cors: Cors{
				Origins: []string{"*"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			Cors: Cors{
				Origins: []string{"*", "https://examples.com"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*,https://examples.com",
			},
		},
		{
			Cors: Cors{
				Origins: []string{"*", "https://examples.com"},
				Methods: []string{"GET", "POST"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin":  "*,https://examples.com",
				"Access-Control-Allow-Methods": "GET,POST",
			},
		},
	}

	for i, c := range cases {
		cfg := newFakeKeycloakConfig()
		// update the cors options
		cfg.EnableCorsGlobal = true
		cfg.NoRedirects = false
		cfg.CorsCredentials = c.Cors.Credentials
		cfg.CorsExposedHeaders = c.Cors.ExposedHeaders
		cfg.CorsHeaders = c.Cors.Headers
		cfg.CorsMaxAge = c.Cors.MaxAge
		cfg.CorsMethods = c.Cors.Methods
		cfg.CorsOrigins = c.Cors.Origins
		// create the test service
		svc := newTestServiceWithConfig(cfg)
		// login and get a token
		token, err := makeTestOauthLogin(svc + fakeAuthAllURL)
		if err != nil {
			t.Errorf("case %d, unable to login to service, error: %s", i, err)
			continue
		}
		// make a request and check the response
		var response testUpstreamResponse
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetAuthToken(token).
			SetResult(&response).
			Get(svc + fakeAuthAllURL)
		if !assert.NoError(t, err, "case %d, unable to make request, error: %s", i, err) {
			continue
		}
		// make sure we got a successfully response
		if !assert.Equal(t, http.StatusOK, resp.StatusCode(), "case %d expected response: %d, got: %d", i, http.StatusOK, resp.StatusCode()) {
			continue
		}
		// parse the response
		assert.NotEmpty(t, response.Headers, "case %d the headers should not be empty", i)
		// check the headers are present
		for k, v := range c.Headers {
			assert.NotEmpty(t, resp.Header().Get(k), "case %d did not find header: %s", i, k)
			assert.Equal(t, v, resp.Header().Get(k), "case %d expected: %s, got: %s", i, v, resp.Header().Get(k))
		}
	}
}

func TestCustomHeadersHandler(t *testing.T) {
	cs := []struct {
		Match   []string
		Claims  jose.Claims
		Expects map[string]string
	}{ /*
			{
				Match: []string{"subject", "userid", "email", "username"},
				Claims: jose.Claims{
					"id":    "test-subject",
					"name":  "rohith",
					"email": "gambol99@gmail.com",
				},
				Expects: map[string]string{
					"X-Auth-Subject":  "test-subject",
					"X-Auth-Userid":   "rohith",
					"X-Auth-Email":    "gambol99@gmail.com",
					"X-Auth-Username": "rohith",
				},
			},
			{
				Match: []string{"roles"},
				Claims: jose.Claims{
					"roles": []string{"a", "b", "c"},
				},
				Expects: map[string]string{
					"X-Auth-Roles": "a,b,c",
				},
			},*/
		{
			Match: []string{"given_name", "family_name"},
			Claims: jose.Claims{
				"email":              "gambol99@gmail.com",
				"name":               "Rohith Jayawardene",
				"family_name":        "Jayawardene",
				"preferred_username": "rjayawardene",
				"given_name":         "Rohith",
			},
			Expects: map[string]string{
				"X-Auth-Given-Name":  "Rohith",
				"X-Auth-Family-Name": "Jayawardene",
			},
		},
	}
	for i, x := range cs {
		cfg := newFakeKeycloakConfig()
		cfg.AddClaims = x.Match
		_, idp, svc := newTestProxyService(cfg)
		// create a token with those clams
		token := newTestToken(idp.getLocation())
		token.mergeClaims(x.Claims)
		signed, _ := idp.signToken(token.claims)
		// make the request
		var response testUpstreamResponse
		resp, err := resty.New().SetAuthToken(signed.Encode()).R().SetResult(&response).Get(svc + fakeAuthAllURL)
		if !assert.NoError(t, err, "case %d, unable to make the request, error: %s", i, err) {
			continue
		}
		// ensure the headers
		if !assert.Equal(t, http.StatusOK, resp.StatusCode(), "case %d, expected: %d, got: %d", i, http.StatusOK, resp.StatusCode()) {
			continue
		}
		for k, v := range x.Expects {
			assert.NotEmpty(t, response.Headers.Get(k), "case %d, did not have header: %s", i, k)
			assert.Equal(t, v, response.Headers.Get(k), "case %d, expected: %s, got: %s", i, v, response.Headers.Get(k))
		}
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
			Roles:   []string{"admin"},
		},
		{
			URL:     "/test",
			Methods: []string{"GET"},
			Roles:   []string{"test"},
		},
		{
			URL:     "/either",
			Methods: []string{"ANY"},
			Roles:   []string{"admin", "test"},
		},
		{
			URL:     "/",
			Methods: []string{"ANY"},
		},
	}
	_, idp, svc := newTestProxyService(cfg)
	cs := []struct {
		Method   string
		URL      string
		Roles    []string
		Expected int
	}{
		{
			URL:      "/admin",
			Roles:    []string{},
			Expected: http.StatusForbidden,
		},
		{
			URL:      "/admin",
			Roles:    []string{"admin"},
			Expected: http.StatusOK,
		},
		{
			URL:      "/test",
			Expected: http.StatusOK,
			Roles:    []string{"test"},
		},
		{
			URL:      "/either",
			Expected: http.StatusOK,
			Roles:    []string{"test", "admin"},
		},
		{
			URL:      "/either",
			Expected: http.StatusForbidden,
			Roles:    []string{"no_roles"},
		},
		{
			URL:      "/",
			Expected: http.StatusOK,
		},
	}

	for _, c := range cs {
		// step: create token from the toles
		token := newTestToken(idp.getLocation())
		if len(c.Roles) > 0 {
			token.setRealmsRoles(c.Roles)
		}
		jwt, err := idp.signToken(token.claims)
		if !assert.NoError(t, err) {
			continue
		}

		// step: make the request
		resp, err := resty.New().R().
			SetAuthToken(jwt.Encode()).
			Get(svc + c.URL)
		if !assert.NoError(t, err) {
			continue
		}
		assert.Equal(t, c.Expected, resp.StatusCode())
		if c.Expected == http.StatusOK {
			assert.NotEmpty(t, resp.Header().Get(testProxyAccepted))
		}
	}
}

func TestRolesAdmissionHandlerClaims(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.NoRedirects = true
	cfg.Resources = []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
	}
	cs := []struct {
		Matches  map[string]string
		Claims   jose.Claims
		Expected int
	}{
		{
			Matches:  map[string]string{"cal": "test"},
			Claims:   jose.Claims{},
			Expected: http.StatusForbidden,
		},
		{
			Matches:  map[string]string{"item": "^tes$"},
			Claims:   jose.Claims{},
			Expected: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"item": "^tes$"},
			Claims: jose.Claims{
				"item": "tes",
			},
			Expected: http.StatusOK,
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Claims: jose.Claims{
				"item": "test",
			},
			Expected: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"item": "^test", "found": "something"},
			Claims: jose.Claims{
				"item":  "tester",
				"found": "something",
			},
			Expected: http.StatusOK,
		},
		{
			Matches: map[string]string{"item": ".*"},
			Claims: jose.Claims{
				"item": "test",
			},
			Expected: http.StatusOK,
		},
		{
			Matches:  map[string]string{"item": "^t.*$"},
			Claims:   jose.Claims{"item": "test"},
			Expected: http.StatusOK,
		},
	}

	for i, c := range cs {
		cfg.MatchClaims = c.Matches
		_, idp, svc := newTestProxyService(cfg)

		token := newTestToken(idp.getLocation())
		token.mergeClaims(c.Claims)
		jwt, err := idp.signToken(token.claims)
		if !assert.NoError(t, err) {
			continue
		}
		// step: inject a resource
		resp, err := resty.New().R().
			SetAuthToken(jwt.Encode()).
			Get(svc + "/admin")
		if !assert.NoError(t, err) {
			continue
		}
		assert.Equal(t, c.Expected, resp.StatusCode(), "case %d failed, expected: %d but got: %d", i, c.Expected, resp.StatusCode())
		if c.Expected == http.StatusOK {
			assert.NotEmpty(t, resp.Header().Get(testProxyAccepted))
		}
	}
}

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

	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func BenchmarkEntrypointHandler(b *testing.B) {
	p, _, _ := newTestProxyService(nil)
	handler := p.entrypointMiddleware()

	for n := 0; n < b.N; n++ {
		handler(newFakeGinContext("GET", "/"))
	}
}

func TestEntrypointHandlerSecure(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:         "/admin/white_listed",
			WhiteListed: true,
		},
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
		{
			URL:     "/",
			Methods: []string{"POST"},
			Roles:   []string{"test"},
		},
	})

	handler := proxy.entrypointMiddleware()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", "/")},
		{Context: newFakeGinContext("GET", "/admin"), Secure: true},
		{Context: newFakeGinContext("GET", "/admin/white_listed")},
		{Context: newFakeGinContext("GET", "/admin/white"), Secure: true},
		{Context: newFakeGinContext("GET", "/not_secure")},
		{Context: newFakeGinContext("POST", "/"), Secure: true},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}
}

func TestEntrypointMethods(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:     "/u0",
			Methods: []string{"GET", "POST"},
		},
		{
			URL:     "/u1",
			Methods: []string{"ANY"},
		},
		{
			URL:     "/u2",
			Methods: []string{"POST", "PUT"},
		},
	})

	handler := proxy.entrypointMiddleware()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", "/u0"), Secure: true},
		{Context: newFakeGinContext("POST", "/u0"), Secure: true},
		{Context: newFakeGinContext("PUT", "/u0"), Secure: false},
		{Context: newFakeGinContext("GET", "/u1"), Secure: true},
		{Context: newFakeGinContext("POST", "/u1"), Secure: true},
		{Context: newFakeGinContext("PATCH", "/u1"), Secure: true},
		{Context: newFakeGinContext("POST", "/u2"), Secure: true},
		{Context: newFakeGinContext("PUT", "/u2"), Secure: true},
		{Context: newFakeGinContext("DELETE", "/u2"), Secure: false},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}
}

func TestEntrypointWhiteListing(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:         "/admin/white_listed",
			WhiteListed: true,
		},
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
	})
	handler := proxy.entrypointMiddleware()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", "/")},
		{Context: newFakeGinContext("GET", "/admin"), Secure: true},
		{Context: newFakeGinContext("GET", "/admin/white_listed")},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}

}

func TestEntrypointHandler(t *testing.T) {
	proxy, _, _ := newTestProxyService(nil)
	handler := proxy.entrypointMiddleware()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext(http.MethodGet, fakeAdminRoleURL), Secure: true},
		{Context: newFakeGinContext(http.MethodGet, fakeAdminRoleURL+"/sso"), Secure: true},
		{Context: newFakeGinContext(http.MethodGet, fakeAdminRoleURL+"/../sso"), Secure: true},
		{Context: newFakeGinContext(http.MethodGet, "/not_secure")},
		{Context: newFakeGinContext(http.MethodGet, fakeTestWhitelistedURL)},
		{Context: newFakeGinContext(http.MethodGet, oauthURL)},
		{Context: newFakeGinContext(http.MethodGet, fakeTestListenOrdered), Secure: true},
	}

	for i, c := range tests {
		handler(c.Context)
		_, found := c.Context.Get(cxEnforce)
		if c.Secure && !found {
			t.Errorf("test case %d should have been set secure", i)
		}
		if !c.Secure && found {
			t.Errorf("test case %d should not have been set secure", i)
		}
	}
}

func TestSecurityHandler(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	handler := p.securityMiddleware()
	context := newFakeGinContext("GET", "/")
	handler(context)

	assert.Equal(t, http.StatusOK, context.Writer.Status(),
		"we should have received a 200 not %d", context.Writer.Status())

	p, _, _ = newTestProxyService(nil)
	p.config.Hostnames = []string{"127.0.0.1"}
	handler = p.securityMiddleware()
	handler(context)
	assert.Equal(t, http.StatusOK, context.Writer.Status(),
		"we should have received a 200 not %d", context.Writer.Status())

	p, _, _ = newTestProxyService(nil)
	p.config.Hostnames = []string{"127.0.0.2"}
	handler = p.securityMiddleware()
	handler(context)

	assert.Equal(t, http.StatusInternalServerError, context.Writer.Status(),
		"we should have received a 500 not %d", context.Writer.Status())
}

func TestCrossSiteHandler(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	cases := []struct {
		Method  string
		URI     string
		Cors    Cors
		Headers map[string]string
	}{
		{
			Method: http.MethodGet,
			URI:    "/oauth/test",
			Cors: Cors{
				Origins: []string{"*"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			Method: http.MethodGet,
			URI:    "/oauth/test",
			Cors: Cors{
				Origins: []string{"*", "https://examples.com"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*,https://examples.com",
			},
		},
		{
			Method: http.MethodGet,
			URI:    "/foo",
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
		handler := p.corsMiddleware(c.Cors)
		// call the handler and check the responses
		context := newFakeGinContext(c.Method, c.URI)
		handler(context)
		// step: check the headers
		for k, v := range c.Headers {
			value := context.Writer.Header().Get(k)
			if value == "" {
				t.Errorf("case %d, should have had the %s header set, headers: %v",
					i, k, context.Writer.Header())
				continue
			}
			if value != v {
				t.Errorf("case %d, expected: %s but got %s", i, k, value)
			}
		}
	}
}

func TestCustomHeadersHandler(t *testing.T) {
	p, _, _ := newTestProxyService(nil)

	cases := []struct {
		Identity     *userContext
		CustomClaims []string
		Expected     http.Header
	}{
		{
			Expected: http.Header{},
		},
		{
			Identity: &userContext{
				id:    "test-subject",
				name:  "rohith",
				email: "gambol99@gmail.com",
			},
			Expected: http.Header{
				"X-Auth-Subject":  []string{"test-subject"},
				"X-Auth-Userid":   []string{"rohith"},
				"X-Auth-Email":    []string{"gambol99@gmail.com"},
				"X-Auth-Username": []string{"rohith"},
			},
		},
		{

			Identity: &userContext{
				roles: []string{"a", "b", "c"},
			},
			Expected: http.Header{
				"X-Auth-Roles": []string{"a,b,c"},
			},
		},
		{
			CustomClaims: []string{"given_name", "family_name"},
			Identity: &userContext{
				claims: jose.Claims{
					"email":              "gambol99@gmail.com",
					"name":               "Rohith Jayawardene",
					"family_name":        "Jayawardene",
					"preferred_username": "rjayawardene",
					"given_name":         "Rohith",
				},
			},
			Expected: http.Header{
				"X-Auth-Given-Name":  []string{"Rohith"},
				"X-Auth-Family-Name": []string{"Jayawardene"},
			},
		},
	}
	for i, x := range cases {
		handler := p.headersMiddleware(x.CustomClaims)
		context := newFakeGinContext("GET", "/nothing")
		if x.Identity != nil {
			context.Set(userContextName, x.Identity)
		}
		handler(context)
		// step: and check we have all the headers
		for k := range x.Expected {
			assert.Equal(t,
				x.Expected.Get(k),
				context.Request.Header.Get(k),
				"case %d, expected (%s: %s) got: (%s: %s)",
				i, k, x.Expected.Get(k), k, context.Request.Header.Get(k))
		}
	}
}

func TestHeaderMiddlewareAuthorizationHeader(t *testing.T) {
	cases := []struct {
		Identity *userContext
		Expected http.Header
		Enabled  bool
	}{
		{
			Enabled: true,
			Identity: &userContext{
				email: "gambol99@gmail.com",
			},
			Expected: http.Header{
				"X-Auth-Email":  []string{"gambol99@gmail.com"},
				"Authorization": []string{"Bearer .."},
			},
		},
		{
			Enabled: false,
			Identity: &userContext{
				email: "gambol99@gmail.com",
			},
			Expected: http.Header{
				"X-Auth-Email":  []string{"gambol99@gmail.com"},
				"Authorization": []string{""},
			},
		},
	}
	for i, x := range cases {
		config := newFakeKeycloakConfig()
		config.EnableAuthorizationHeader = x.Enabled

		// step: create the test proxy
		p, _, _ := newTestProxyService(config)
		context := newFakeGinContext("GET", "/test_url")
		if x.Identity != nil {
			context.Set(userContextName, x.Identity)
		}

		// step: create a middleware handler
		handler := p.headersMiddleware([]string{})
		handler(context)

		// step: and check we have all the headers
		for k := range x.Expected {
			assert.Equal(t, x.Expected.Get(k), context.Request.Header.Get(k),
				"case %d, expected (%s: %s) got: (%s: %s)",
				i, k, x.Expected.Get(k), k, context.Request.Header.Get(k))
		}
	}
}

func TestAdmissionHandlerRoles(t *testing.T) {
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
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
	})
	handler := proxy.admissionMiddleware()

	tests := []struct {
		Context     *gin.Context
		UserContext *userContext
		HTTPCode    int
	}{
		{
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Context:  newFakeGinContext("GET", "/admin"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				audience: "test",
				roles:    []string{"admin"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/test"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				audience: "test",
				roles:    []string{"test"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/either"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				audience: "test",
				roles:    []string{"test", "admin"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/either"),
			HTTPCode: http.StatusForbidden,
			UserContext: &userContext{
				audience: "test",
				roles:    []string{"no_roles"},
			},
		},
		{
			Context:  newFakeGinContext("GET", "/"),
			HTTPCode: http.StatusOK,
			UserContext: &userContext{
				audience: "test",
			},
		},
	}

	for i, c := range tests {
		// step: find the resource and inject into the context
		for _, r := range proxy.config.Resources {
			if strings.HasPrefix(c.Context.Request.URL.Path, r.URL) {
				c.Context.Set(cxEnforce, r)
				break
			}
		}
		if _, found := c.Context.Get(cxEnforce); !found {
			t.Errorf("test case %d unable to find a resource for context", i)
			continue
		}

		c.Context.Set(userContextName, c.UserContext)

		handler(c.Context)
		status := c.Context.Writer.Status()
		assert.Equal(t, c.HTTPCode, status, "test case %d should have received code: %d, got %d", i, c.HTTPCode, status)
	}
}

func TestAdmissionHandlerClaims(t *testing.T) {
	// allow any fake authd users
	proxy := newFakeKeycloakProxyWithResources(t, []*Resource{
		{
			URL:     "/admin",
			Methods: []string{"ANY"},
		},
	})

	tests := []struct {
		Matches     map[string]string
		Context     *gin.Context
		UserContext *userContext
		HTTPCode    int
	}{
		{
			Matches: map[string]string{"iss": "test"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims:   jose.Claims{},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^tes$"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims: jose.Claims{
					"aud": "test",
					"iss": 1,
				},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^tes$"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims: jose.Claims{
					"aud": "test",
					"iss": "bad_match",
				},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^test", "notfound": "someting"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims: jose.Claims{
					"aud": "test",
					"iss": "test",
				},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": "^test", "notfound": "someting"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims: jose.Claims{
					"aud": "test",
					"iss": "test",
				},
			},
			HTTPCode: http.StatusForbidden,
		},
		{
			Matches: map[string]string{"iss": ".*"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims: jose.Claims{
					"aud": "test",
					"iss": "test",
				},
			},
			HTTPCode: http.StatusOK,
		},
		{
			Matches: map[string]string{"iss": "^t.*$"},
			Context: newFakeGinContext("GET", "/admin"),
			UserContext: &userContext{
				audience: "test",
				claims:   jose.Claims{"iss": "test"},
			},
			HTTPCode: http.StatusOK,
		},
	}

	for i, c := range tests {
		// step: if closure so we need to get the handler each time
		proxy.config.MatchClaims = c.Matches
		handler := proxy.admissionMiddleware()
		// step: inject a resource

		c.Context.Set(cxEnforce, proxy.config.Resources[0])
		c.Context.Set(userContextName, c.UserContext)

		handler(c.Context)
		c.Context.Writer.WriteHeaderNow()
		status := c.Context.Writer.Status()
		assert.Equal(t, c.HTTPCode, status, "test case %d should have received code: %d, got %d", i, c.HTTPCode, status)
	}
}

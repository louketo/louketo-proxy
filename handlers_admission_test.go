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
)

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
	handler := proxy.admissionHandler()

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
		if c.Context.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved code: %d, got %d", i, c.HTTPCode, c.Context.Writer.Status())
		}
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
		proxy.config.ClaimsMatch = c.Matches
		handler := proxy.admissionHandler()
		// step: inject a resource

		c.Context.Set(cxEnforce, proxy.config.Resources[0])
		c.Context.Set(userContextName, c.UserContext)

		handler(c.Context)
		c.Context.Writer.WriteHeaderNow()

		if c.Context.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved code: %d, got %d", i, c.HTTPCode, c.Context.Writer.Status())
		}
	}
}

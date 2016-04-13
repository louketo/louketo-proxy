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
	"testing"

	"github.com/gin-gonic/gin"
)

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

	handler := proxy.entryPointHandler()

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

	handler := proxy.entryPointHandler()

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
	handler := proxy.entryPointHandler()

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
	proxy := newFakeKeycloakProxy(t)
	handler := proxy.entryPointHandler()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{Context: newFakeGinContext("GET", fakeAdminRoleURL), Secure: true},
		{Context: newFakeGinContext("GET", fakeAdminRoleURL+"/sso"), Secure: true},
		{Context: newFakeGinContext("GET", fakeAdminRoleURL+"/../sso"), Secure: true},
		{Context: newFakeGinContext("GET", "/not_secure")},
		{Context: newFakeGinContext("GET", fakeTestWhitelistedURL)},
		{Context: newFakeGinContext("GET", oauthURL)},
		{Context: newFakeGinContext("GET", fakeTestListenOrdered), Secure: true},
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

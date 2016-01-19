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
	"testing"

	"github.com/gambol99/go-oidc/jose"
	"github.com/gin-gonic/gin"
)

func TestEntrypointHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)
	handler := proxy.entrypointHandler()

	tests := []struct {
		Context *gin.Context
		Secure  bool
	}{
		{
			Context: newFakeGinContext("GET", fakeAdminRoleURL), Secure: true,
		},
		{
			Context: newFakeGinContext("GET", fakeAdminRoleURL+"/sso"), Secure: true,
		},
		{
			Context: newFakeGinContext("GET", fakeAdminRoleURL+"/../sso"), Secure: true,
		},
		{
			Context: newFakeGinContext("GET", "/not_secure"),
		},
		{
			Context: newFakeGinContext("GET", fakeTestWhitelistedURL),
		},
		{
			Context: newFakeGinContext("GET", oauthURL),
		},
		{
			Context: newFakeGinContext("GET", faketestListenOrdered), Secure: true,
		},
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

func TestAdmissionHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)
	handler := proxy.admissionHandler()
	tests := []struct {
		Context     *gin.Context
		Resource    *Resource
		UserContext *userContext
		HTTPCode    int
	}{
		{
			Context:  newFakeGinContext("GET", ""),
			HTTPCode: http.StatusOK,
		},
		{
			Context:  newFakeGinContext("GET", "/admin"),
			HTTPCode: http.StatusForbidden,
			Resource: &Resource{
				URL:          fakeAdminRoleURL,
				Methods:      []string{"GET"},
				RolesAllowed: []string{fakeAdminRole},
			},
			UserContext: &userContext{
				roles: []string{},
			},
		},
		{
			Context:  newFakeGinContext("GET", fakeAdminRoleURL),
			HTTPCode: http.StatusOK,
			Resource: &Resource{
				URL:          fakeAdminRoleURL,
				Methods:      []string{"GET"},
				RolesAllowed: []string{fakeAdminRole},
			},
			UserContext: &userContext{
				roles:  []string{fakeAdminRole},
				claims: jose.Claims{"aud": fakeClientID},
			},
		},
		{
			Context:  newFakeGinContext("GET", fakeAdminRoleURL+"/sso"),
			HTTPCode: http.StatusOK,
			Resource: &Resource{
				URL:          fakeAdminRoleURL,
				Methods:      []string{"GET"},
				RolesAllowed: []string{fakeAdminRole},
			},
			UserContext: &userContext{
				roles:  []string{fakeTestRole, fakeAdminRole},
				claims: jose.Claims{"aud": fakeClientID},
			},
		},
		{
			Context:  newFakeGinContext("GET", fakeTestRoleURL),
			HTTPCode: http.StatusForbidden,
			Resource: &Resource{
				URL:          fakeAdminRoleURL,
				Methods:      []string{"GET"},
				RolesAllowed: []string{fakeTestRole, "test"},
			},
			UserContext: &userContext{
				roles:  []string{fakeTestRole, fakeAdminRole},
				claims: jose.Claims{"aud": fakeClientID},
			},
		},
		{
			Context:  newFakeGinContext("GET", fakeAdminRoleURL),
			HTTPCode: http.StatusForbidden,
			Resource: &Resource{
				URL:          fakeAdminRoleURL,
				Methods:      []string{"GET"},
				RolesAllowed: []string{fakeTestRole, "test"},
			},
			UserContext: &userContext{
				roles: []string{fakeTestRole, fakeAdminRole},
			},
		},
		{
			Context:  newFakeGinContext("POST", fakeAdminRoleURL),
			HTTPCode: http.StatusForbidden,
			Resource: &Resource{
				URL:          fakeAdminRoleURL,
				Methods:      []string{"POST"},
				RolesAllowed: []string{fakeTestRole, "test"},
			},
			UserContext: &userContext{
				roles: []string{fakeTestRole, fakeAdminRole},
			},
		},
	}

	for i, c := range tests {
		if c.Resource != nil {
			c.Context.Set(cxEnforce, c.Resource)
		}
		if c.UserContext != nil {
			c.Context.Set(userContextName, c.UserContext)
		}
		handler(c.Context)
		if c.Context.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved code: %d, got %d", i, c.HTTPCode, c.Context.Writer.Status())
		}
	}
}

func TestHealthHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)
	context := newFakeGinContext("GET", healthURL)
	proxy.healthHandler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have recieved a 200 response")
	}
}

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
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
)

func TestExpirationHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)

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
		if cx.Writer.Status() != c.HTTPCode {
			t.Errorf("test case %d should have recieved: %d, but got %d", i, c.HTTPCode, cx.Writer.Status())
		}
	}
}

func TestCrossSiteHandler(t *testing.T) {
	kc := newFakeKeycloakProxy(t)
	handler := kc.crossSiteHandler()

	cases := []struct {
		Cors    *CORS
		Headers map[string]string
	}{
		{
			Cors: &CORS{
				Origins: []string{"*"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin": "*",
			},
		},
		{
			Cors: &CORS{
				Origins: []string{"*", "https://examples.com"},
				Methods: []string{"GET"},
			},
			Headers: map[string]string{
				"Access-Control-Allow-Origin":  "*,https://examples.com",
				"Access-Control-Allow-Methods": "GET",
			},
		},
	}

	for i, c := range cases {
		// step: get the config
		kc.config.CORS = c.Cors
		// call the handler and check the responses
		context := newFakeGinContext("GET", "/oauth/test")
		handler(context)
		// step: check the headers
		for k, v := range c.Headers {
			value := context.Writer.Header().Get(k)
			if value == "" {
				t.Errorf("case %d, should have had the %s header set, headers: %v", i, k, context.Writer.Header())
				continue
			}
			if value != v {
				t.Errorf("case %d, expected: %s but got %s", i, k, value)
			}
		}
	}
}

func TestSecurityHandler(t *testing.T) {
	kc := newFakeKeycloakProxy(t)
	handler := kc.securityHandler()
	context := newFakeGinContext("GET", "/")
	handler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have received a 200")
	}

	kc = newFakeKeycloakProxy(t)
	kc.config.Hostnames = []string{"127.0.0.1"}
	handler = kc.securityHandler()
	handler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have received a 200 not %d", context.Writer.Status())
	}

	kc = newFakeKeycloakProxy(t)
	kc.config.Hostnames = []string{"127.0.0.2"}
	handler = kc.securityHandler()
	handler(context)
	if context.Writer.Status() != http.StatusInternalServerError {
		t.Errorf("we should have received a 500 not %d", context.Writer.Status())
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

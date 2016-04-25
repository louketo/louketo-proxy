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

func TestHealthHandler(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)
	context := newFakeGinContext("GET", healthURL)
	proxy.healthHandler(context)
	if context.Writer.Status() != http.StatusOK {
		t.Errorf("we should have recieved a 200 response")
	}
}

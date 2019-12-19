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

	"github.com/stretchr/testify/assert"
)

func TestGetIndentity(t *testing.T) {
	p, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation()).getToken()
	encoded := token.Encode()

	testCases := []struct {
		Request *http.Request
		Ok      bool
	}{
		{
			Request: &http.Request{
				Header: http.Header{
					"Authorization": []string{fmt.Sprintf("Bearer %s", encoded)},
				},
			},
			Ok: true,
		},
		{
			Request: &http.Request{
				Header: http.Header{
					"Authorization": []string{"Basic QWxhZGRpbjpPcGVuU2VzYW1l"},
				},
			},
		},
		{
			Request: &http.Request{
				Header: http.Header{
					"Authorization": []string{fmt.Sprintf("Test %s", encoded)},
				},
			},
		},
		{
			Request: &http.Request{
				Header: http.Header{},
			},
		},
	}

	for i, c := range testCases {
		user, err := p.getIdentity(c.Request)
		if err != nil && c.Ok {
			t.Errorf("test case %d should not have errored", i)
			continue
		}
		if err != nil && !c.Ok {
			continue
		}
		if user.token.Encode() != encoded {
			t.Errorf("test case %d the tokens are not the same", i)
		}
	}
}

func TestGetTokenInRequest(t *testing.T) {
	defaultName := newDefaultConfig().CookieAccessName
	token := newTestToken("test").getToken()
	cs := []struct {
		Token      string
		AuthScheme string
		Error      error
	}{
		{
			Token:      "",
			AuthScheme: "",
			Error:      ErrSessionNotFound,
		},
		{
			Token:      token.Encode(),
			AuthScheme: "",
			Error:      nil,
		},
		{
			Token:      token.Encode(),
			AuthScheme: "Bearer",
			Error:      nil,
		},
		{
			Token:      "QWxhZGRpbjpPcGVuU2VzYW1l",
			AuthScheme: "Basic",
			Error:      ErrSessionNotFound,
		},
		{
			Token:      token.Encode(),
			AuthScheme: "Test",
			Error:      ErrSessionNotFound,
		},
	}
	for i, x := range cs {
		req := newFakeHTTPRequest(http.MethodGet, "/")
		if x.Token != "" {
			if x.AuthScheme != "" {
				req.Header.Set(authorizationHeader, x.AuthScheme+" "+x.Token)
			} else {
				req.AddCookie(&http.Cookie{
					Name:   defaultName,
					Path:   req.URL.Path,
					Domain: req.Host,
					Value:  x.Token,
				})
			}
		}
		access, bearer, err := getTokenInRequest(req, defaultName)
		switch x.Error {
		case nil:
			assert.NoError(t, err, "case %d should not have thrown an error", i)
			assert.Equal(t, x.AuthScheme == "Bearer", bearer)
			assert.Equal(t, token.Encode(), access)
		default:
			assert.Equal(t, x.Error, err, "case %d, expected error: %s", i, x.Error)
		}
	}
}

func TestGetRefreshTokenFromCookie(t *testing.T) {
	p, _, _ := newTestProxyService(nil)
	cases := []struct {
		Cookies  *http.Cookie
		Expected string
		Ok       bool
	}{
		{
			Cookies: &http.Cookie{},
		},
		{
			Cookies: &http.Cookie{
				Name:   "not_a_session_cookie",
				Path:   "/",
				Domain: "127.0.0.1",
			},
		},
		{
			Cookies: &http.Cookie{
				Name:   "kc-state",
				Path:   "/",
				Domain: "127.0.0.1",
				Value:  "refresh_token",
			},
			Expected: "refresh_token",
			Ok:       true,
		},
	}

	for _, x := range cases {
		req := newFakeHTTPRequest(http.MethodGet, "/")
		req.AddCookie(x.Cookies)
		token, err := p.getRefreshTokenFromCookie(req)
		switch x.Ok {
		case true:
			assert.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.Equal(t, x.Expected, token)
		default:
			assert.Error(t, err)
			assert.Empty(t, token)
		}
	}
}

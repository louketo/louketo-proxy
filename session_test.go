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

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGetSessionToken(t *testing.T) {
	token := getFakeAccessToken(t)
	encoded := token.Encode()

	testCases := []struct {
		Context *gin.Context
		Ok      bool
	}{
		{
			Context: &gin.Context{
				Request: &http.Request{
					Header: http.Header{
						"Authorization": []string{fmt.Sprintf("Bearer %s", encoded)},
					},
				},
			},
			Ok: true,
		},
		{
			Context: &gin.Context{
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		// @TODO need to other checks
	}

	for i, c := range testCases {
		user, err := getIdentity(c.Context)
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

func TestGetRefreshTokenFromCookie(t *testing.T) {
	cases := []struct {
		Cookies  []*http.Cookie
		Expected string
		Ok       bool
	}{
		{
			Cookies: []*http.Cookie{},
		},
		{
			Cookies: []*http.Cookie{
				{
					Name:   "not_a_session_cookie",
					Path:   "/",
					Domain: "127.0.0.1",
				},
			},
		},
		{
			Cookies: []*http.Cookie{
				{
					Name:   cookieRefreshToken,
					Path:   "/",
					Domain: "127.0.0.1",
					Value:  "refresh_token",
				},
			},
			Expected: "refresh_token",
			Ok:       true,
		},
	}

	for i, x := range cases {
		context := newFakeGinContextWithCookies("GET", "/", x.Cookies)

		token, err := getRefreshTokenFromCookie(context)
		if err != nil && x.Ok {
			t.Errorf("case %d, should not have thrown an error: %s, headers: %v", i, err, context.Writer.Header())
			continue
		}
		if err == nil && !x.Ok {
			t.Errorf("case %d, should have thrown an error", i)
			continue
		}
		assert.Equal(t, x.Expected, token, "case %d, expected token: %v, got: %v", x.Expected, token)
	}
}

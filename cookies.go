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
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
)

//
// dropCookie drops a cookie into the response
//
func dropCookie(cx *gin.Context, name, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Domain:   strings.Split(cx.Request.Host, ":")[0],
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Value:    value,
	}
	if !expires.IsZero() {
		cookie.Expires = expires
	}

	http.SetCookie(cx.Writer, cookie)
}

//
// dropAccessTokenCookie drops a access token cookie into the response
//
func dropAccessTokenCookie(cx *gin.Context, token jose.JWT) {
	dropCookie(cx, cookieAccessToken, token.Encode(), time.Time{})
}

//
// dropRefreshTokenCookie drops a refresh token cookie into the response
//
func dropRefreshTokenCookie(cx *gin.Context, token string, expires time.Time) {
	dropCookie(cx, cookieRefreshToken, token, expires)
}

//
// clearAllCookies is just a helper function for the below
//
func clearAllCookies(cx *gin.Context) {
	clearAccessTokenCookie(cx)
	clearRefreshTokenCookie(cx)
}

//
// clearRefreshSessionCookie clears the session cookie
//
func clearRefreshTokenCookie(cx *gin.Context) {
	dropCookie(cx, cookieRefreshToken, "", time.Now().Add(-1*time.Hour))
}

//
// clearAccessTokenCookie clears the session cookie
//
func clearAccessTokenCookie(cx *gin.Context) {
	dropCookie(cx, cookieAccessToken, "", time.Now().Add(-1*time.Hour))
}

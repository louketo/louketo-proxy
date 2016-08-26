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

	"github.com/gin-gonic/gin"
)

//
// dropCookie drops a cookie into the response
//
func (r *oauthProxy) dropCookie(cx *gin.Context, name, value string, duration time.Duration) {
	// step: default to the host header, else the config domain
	domain := strings.Split(cx.Request.Host, ":")[0]
	if r.config.CookieDomain != "" {
		domain = r.config.CookieDomain
	}
	cookie := &http.Cookie{
		Name:     name,
		Domain:   domain,
		HttpOnly: r.config.HTTPOnlyCookie,
		Path:     "/",
		Secure:   r.config.SecureCookie,
		Value:    value,
	}
	if duration != 0 {
		cookie.Expires = time.Now().Add(duration)
	}

	http.SetCookie(cx.Writer, cookie)
}

//
// dropAccessTokenCookie drops a access token cookie into the response
//
func (r *oauthProxy) dropAccessTokenCookie(cx *gin.Context, value string, duration time.Duration) {
	r.dropCookie(cx, r.config.CookieAccessName, value, duration)
}

//
// dropRefreshTokenCookie drops a refresh token cookie into the response
//
func (r *oauthProxy) dropRefreshTokenCookie(cx *gin.Context, value string, duration time.Duration) {
	r.dropCookie(cx, r.config.CookieRefreshName, value, duration)
}

//
// clearAllCookies is just a helper function for the below
//
func (r *oauthProxy) clearAllCookies(cx *gin.Context) {
	r.clearAccessTokenCookie(cx)
	r.clearRefreshTokenCookie(cx)
}

//
// clearRefreshSessionCookie clears the session cookie
//
func (r *oauthProxy) clearRefreshTokenCookie(cx *gin.Context) {
	r.dropCookie(cx, r.config.CookieRefreshName, "", time.Duration(-10*time.Hour))
}

//
// clearAccessTokenCookie clears the session cookie
//
func (r *oauthProxy) clearAccessTokenCookie(cx *gin.Context) {
	r.dropCookie(cx, r.config.CookieAccessName, "", time.Duration(-10*time.Hour))
}

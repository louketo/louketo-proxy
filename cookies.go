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
)

// dropCookie drops a cookie into the response
func (r *oauthProxy) dropCookie(w http.ResponseWriter, host, name, value string, duration time.Duration) {
	// step: default to the host header, else the config domain
	domain := strings.Split(host, ":")[0]
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

	http.SetCookie(w, cookie)
}

// dropAccessTokenCookie drops a access token cookie into the response
func (r *oauthProxy) dropAccessTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookie(w, req.Host, r.config.CookieAccessName, value, duration)
}

// dropRefreshTokenCookie drops a refresh token cookie into the response
func (r *oauthProxy) dropRefreshTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookie(w, req.Host, r.config.CookieRefreshName, value, duration)
}

// clearAllCookies is just a helper function for the below
func (r *oauthProxy) clearAllCookies(req *http.Request, w http.ResponseWriter) {
	r.clearAccessTokenCookie(req, w)
	r.clearRefreshTokenCookie(req, w)
}

// clearRefreshSessionCookie clears the session cookie
func (r *oauthProxy) clearRefreshTokenCookie(req *http.Request, w http.ResponseWriter) {
	r.dropCookie(w, req.Host, r.config.CookieRefreshName, "", time.Duration(-10*time.Hour))
}

// clearAccessTokenCookie clears the session cookie
func (r *oauthProxy) clearAccessTokenCookie(req *http.Request, w http.ResponseWriter) {
	r.dropCookie(w, req.Host, r.config.CookieAccessName, "", time.Duration(-10*time.Hour))
}

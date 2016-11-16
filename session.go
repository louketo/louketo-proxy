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

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
)

// getIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
func (r *oauthProxy) getIdentity(req *http.Request) (*userContext, error) {
	isBearer := false

	// step: check for a bearer token or cookie with jwt token
	access, isBearer, err := getTokenInRequest(req, r.config.CookieAccessName)
	if err != nil {
		return nil, err
	}
	// step: parse the access token
	token, err := jose.ParseJWT(access)
	if err != nil {
		return nil, err
	}

	// step: parse the access token and extract the user identity
	user, err := extractIdentity(token)
	if err != nil {
		return nil, err
	}

	user.bearerToken = isBearer

	// step: add some logging for debug purposed
	log.WithFields(log.Fields{
		"id":    user.id,
		"name":  user.name,
		"email": user.email,
		"roles": strings.Join(user.roles, ","),
	}).Debugf("found the user identity: %s in the request", user.email)

	return user, nil
}

// getRefreshTokenFromCookie returns the refresh token from the cookie if any
func (r *oauthProxy) getRefreshTokenFromCookie(req *http.Request) (string, error) {
	token, err := getTokenInCookie(req, r.config.CookieRefreshName)
	if err != nil {
		return "", err
	}

	return token, nil
}

// getTokenInRequest returns the access token from the http request
func getTokenInRequest(req *http.Request, name string) (string, bool, error) {
	bearer := true
	// step: check for a token in the authorization header
	token, err := getTokenInBearer(req)
	if err != nil {
		if err != ErrSessionNotFound {
			return "", false, err
		}
		if token, err = getTokenInCookie(req, name); err != nil {
			return token, false, err
		}
		bearer = false
	}

	return token, bearer, nil
}

// getTokenInBearer retrieves a access token from the authorization header
func getTokenInBearer(req *http.Request) (string, error) {
	token := req.Header.Get(authorizationHeader)
	if token == "" {
		return "", ErrSessionNotFound
	}

	items := strings.Split(token, " ")
	if len(items) != 2 {
		return "", ErrInvalidSession
	}

	return items[1], nil
}

// getTokenInCookie retrieves the access token from the request cookies
func getTokenInCookie(req *http.Request, name string) (string, error) {
	cookie := findCookie(name, req.Cookies())
	if cookie == nil {
		return "", ErrSessionNotFound
	}

	return cookie.Value, nil
}

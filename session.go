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
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
)

//
// getIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
//
func (r *oauthProxy) getIdentity(cx *gin.Context) (*userContext, error) {
	isBearer := false

	// step: check for a bearer token or cookie with jwt token
	token, err := r.getAccessTokenFromCookie(cx)
	if err != nil {
		if err != ErrSessionNotFound {
			return nil, err
		}
		// step: else attempt to grab token from the bearer token]
		if token, err = r.getTokenFromBearer(cx); err != nil {
			return nil, err
		}
		isBearer = true
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

//
// getTokenFromBearer attempt to retrieve token from bearer token
//
func (r *oauthProxy) getTokenFromBearer(cx *gin.Context) (jose.JWT, error) {
	auth := cx.Request.Header.Get(authorizationHeader)
	if auth == "" {
		return jose.JWT{}, ErrSessionNotFound
	}

	items := strings.Split(auth, " ")
	if len(items) != 2 {
		return jose.JWT{}, ErrInvalidSession
	}

	return jose.ParseJWT(items[1])
}

//
// getAccessTokenFromCookie attempt to grab access token from cookie
//
func (r *oauthProxy) getAccessTokenFromCookie(cx *gin.Context) (jose.JWT, error) {
	cookie := findCookie(r.config.CookieAccessName, cx.Request.Cookies())
	if cookie == nil {
		return jose.JWT{}, ErrSessionNotFound
	}

	return jose.ParseJWT(cookie.Value)
}

//
// getRefreshTokenFromCookie returns the refresh token from the cookie if any
//
func (r *oauthProxy) getRefreshTokenFromCookie(cx *gin.Context) (string, error) {
	if cookie := findCookie(r.config.CookieRefreshName, cx.Request.Cookies()); cookie != nil {
		return cookie.Value, nil
	}

	return "", ErrSessionNotFound

}

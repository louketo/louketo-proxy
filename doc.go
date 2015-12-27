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
	"errors"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

const (
	prog    = "keycloak-proxy"
	version = "v0.0.2"
	author  = "Rohith"
	email   = "gambol99@gmail.com"

	headerUpgrade          = "Upgrade"
	sessionCookieName      = "keycloak-access"
	sessionStateCookieName = "keycloak-state"
	userContextName        = "identity"

	// the urls
	oauthURL               = "/oauth"
	authorizationURL       = oauthURL + "/authorize"
	callbackURL            = oauthURL + "/callback"
	healthURL              = oauthURL + "/health"
	signInPageURL          = oauthURL + "/sign_in"
	accessForbiddenPageURL = oauthURL + "/forbidden"
)

var (
	// ErrNoCookieFound indicates the cookie has not been found
	ErrNoCookieFound = errors.New("the cookie has not been found")
	// ErrSessionNotFound no session found in the request
	ErrSessionNotFound = errors.New("authentication session not found")
	// ErrNoSessionStateFound means there was not persist state
	ErrNoSessionStateFound = errors.New("no session state found")
	// ErrInvalidSession the session is invalid
	ErrInvalidSession = errors.New("invalid session identifier")
	// ErrAccessTokenExpired indicates the access token has expired
	ErrAccessTokenExpired = errors.New("the access token has expired")
	// ErrRefreshTokenExpired indicates the refresh token as expired
	ErrRefreshTokenExpired = errors.New("the refresh token has expired")
)

// KeycloakProxy is the server component
type KeycloakProxy struct {
	config *Config
	// the gin service
	router *gin.Engine
	// the oidc provider config
	openIDConfig oidc.ClientConfig
	// the oidc client
	openIDClient *oidc.Client
	// the proxy client
	proxy *httputil.ReverseProxy
	// the upstream endpoint
	upstreamURL *url.URL
}

// sessionState holds the state related data
type sessionState struct {
	// the max time the session is permitted
	expireOn time.Time
	// the refresh token if any
	refreshToken string
}

// userContext represents a user
type userContext struct {
	// the id of the user
	id string
	// the email associated to the user
	email string
	// a name of the user
	name string
	// the preferred name
	preferredName string
	// the expiration of the access token
	expiresAt time.Time
	// a set of roles associated
	roles []string
	// the access token itself
	token jose.JWT
	// the claims associated to the token
	claims jose.Claims
}

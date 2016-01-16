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

	"github.com/gambol99/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

const (
	prog        = "keycloak-proxy"
	version     = "v0.0.7"
	author      = "Rohith"
	email       = "gambol99@gmail.com"
	description = "is a proxy using the keycloak service for auth and authorization"

	headerUpgrade          = "Upgrade"
	sessionCookieName      = "kc-access"
	sessionStateCookieName = "kc-state"
	userContextName        = "identity"
	authorizationHeader    = "Authorization"

	// the urls
	oauthURL         = "/oauth"
	authorizationURL = oauthURL + "/authorize"
	callbackURL      = oauthURL + "/callback"
	healthURL        = oauthURL + "/health"
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

// Resource represents a url resource to protect
type Resource struct {
	// URL the url for the resource
	URL string `json:"url" yaml:"url"`
	// Methods the method type
	Methods []string `json:"methods" yaml:"methods"`
	// RolesAllowed the roles required to access this url
	RolesAllowed []string `json:"roles_allowed" yaml:"roles_allowed"`
}

// Config is the configuration for the proxy
type Config struct {
	// LogRequests indicates if we should log all the requests
	LogRequests bool `json:"log_requests" yaml:"log_requests"`
	// LogFormat is the logging format
	LogJSONFormat bool `json:"log_json_format" yaml:"log_json_format"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery_url" yaml:"discovery_url"`
	// ClientID is the client id
	ClientID string `json:"clientid" yaml:"clientid"`
	// Secret is the secret for AS
	Secret string `json:"secret" yaml:"secret"`
	// RedirectionURL the redirection url
	RedirectionURL string `json:"redirection_url" yaml:"redirection_url"`
	// RefreshSession enabled refresh access
	RefreshSession bool `json:"refresh_session" yaml:"refresh_session"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption_key" yaml:"encryption_key"`
	// MaxSession the max session for refreshing
	MaxSession time.Duration `json:"max_session" yaml:"max_session"`
	// ClaimsMatch is a series of checks, the claims in the token must match those here
	ClaimsMatch map[string]string `json:"claims" yaml:"claims"`
	// Listen is the binding interface
	Listen string `json:"listen" yaml:"listen"`
	// ProxyProtocol enables proxy protocol
	ProxyProtocol bool `json:"proxy_protocol" yaml:"proxy_protocol"`
	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `json:"tls_cert" yaml:"tls_cert"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls_private_key" yaml:"tls_private_key"`
	// Upstream is the upstream endpoint i.e whom were proxing to
	Upstream string `json:"upstream" yaml:"upstream"`
	// TagData is passed to the templates
	TagData map[string]string `json:"TagData" yaml:"TagData"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes"`
	// Resources is a list of protected resources
	Resources []*Resource `json:"resources" yaml:"resources"`
	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign_in_page" yaml:"sign_in_page"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `json:"forbidden_page" yaml:"forbidden_page"`
	// SkipTokenVerification tells the service to skipp verifying the access token - for testing purposes
	SkipTokenVerification bool
	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose"`
	// Hostname is a list of hostnames the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames"`
}

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

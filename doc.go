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
	"time"
)

const (
	prog        = "keycloak-proxy"
	version     = "v1.0.0-rc2"
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
	// WhiteListed permits the prefix through
	WhiteListed bool `json:"white-listed" yaml:"white-listed"`
	// Roles the roles required to access this url
	Roles []string `json:"roles" yaml:"roles"`
}

// CORS access controls
type CORS struct {
	// Origins is a list of origins permitted
	Origins []string `json:"origins" yaml:"origins"`
	// Methods is a set of access control methods
	Methods []string `json:"methods" yaml:"methods"`
	// Headers is a set of cors headers
	Headers []string `json:"headers" yaml:"headers"`
	// ExposedHeaders are the exposed header fields
	ExposedHeaders []string `json:"exposed-headers" yaml:"exposed-headers"`
	// Credentials set the creds flag
	Credentials bool `json:"credentials" yaml:"credentials"`
	// MaxAge is the age for CORS
	MaxAge time.Duration `json:"max-age" yaml:"max-age"`
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
	// RefreshSessions enabled refresh access
	RefreshSessions bool `json:"refresh_sessions" yaml:"refresh_sessions"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption_key" yaml:"encryption_key"`
	// MaxSession the max session for refreshing
	MaxSession time.Duration `json:"max_session" yaml:"max_session"`
	// ClaimsMatch is a series of checks, the claims in the token must match those here
	ClaimsMatch map[string]string `json:"claims" yaml:"claims"`
	// Keepalives specifies wheather we use keepalives on the upstream
	Keepalives bool `json:"keepalives" yaml:"keepalives"`
	// Listen is the binding interface
	Listen string `json:"listen" yaml:"listen"`
	// ProxyProtocol enables proxy protocol
	ProxyProtocol bool `json:"proxy_protocol" yaml:"proxy_protocol"`
	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `json:"tls_cert" yaml:"tls_cert"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls_private_key" yaml:"tls_private_key"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `json:"tls_ca_certificate" yaml:"tls_ca_certificate"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream" yaml:"upstream"`
	// TagData is passed to the templates
	TagData map[string]string `json:"TagData" yaml:"TagData"`
	// CORS permits adding headers to the /oauth handlers
	CORS *CORS `json:"cors" yaml:"cors"`
	// Header permits adding customs headers across the board
	Header map[string]string `json:"headers" yaml:"headers"`
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
	// Hostname is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames"`
}

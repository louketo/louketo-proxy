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

var (
	release = "v1.0.6"
	gitsha  = "no gitsha provided"
	version = release + " (git+sha: " + gitsha + ")"
)

const (
	prog        = "keycloak-proxy"
	author      = "Rohith"
	email       = "gambol99@gmail.com"
	description = "is a proxy using the keycloak service for auth and authorization"

	headerUpgrade       = "Upgrade"
	userContextName     = "identity"
	authorizationHeader = "Authorization"
	versionHeader       = "X-Auth-Proxy-Version"

	oauthURL         = "/oauth"
	authorizationURL = "/authorize"
	callbackURL      = "/callback"
	healthURL        = "/health"
	tokenURL         = "/token"
	expiredURL       = "/expired"
	logoutURL        = "/logout"
	loginURL         = "/login"

	claimPreferredName  = "preferred_username"
	claimAudience       = "aud"
	claimResourceAccess = "resource_access"
	claimRealmAccess    = "realm_access"
	claimResourceRoles  = "roles"
)

var (
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
	// ErrNoTokenAudience indicates their is not audience in the token
	ErrNoTokenAudience = errors.New("the token does not audience in claims")
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
	LogRequests bool `json:"log-requests" yaml:"log-requests"`
	// LogFormat is the logging format
	LogJSONFormat bool `json:"log-json-format" yaml:"log-json-format"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery-url" yaml:"discovery-url"`
	// ClientID is the client id
	ClientID string `json:"client-id" yaml:"client-id"`
	// ClientSecret is the secret for AS
	ClientSecret string `json:"client-secret" yaml:"client-secret"`
	// RevocationEndpoint is the token revocation endpoint to revoke refresh tokens
	RevocationEndpoint string `json:"revocation-url" yaml:"revocation-url"`
	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `json:"no-redirects" yaml:"no-redirects"`
	// RedirectionURL the redirection url
	RedirectionURL string `json:"redirection-url" yaml:"redirection-url"`
	// EnableSecurityFilter enabled the security handler
	EnableSecurityFilter bool `json:"enable-security-filter" yaml:"enable-security-filter"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `json:"enable-refresh-tokens" yaml:"enable-refresh-tokens"`
	// CookieAccessName is the name of the access cookie holding the access token
	CookieAccessName string `json:"cookie-access-name" yaml:"cookie-access-name"`
	// CookieRefreshName is the name of the refresh cookie
	CookieRefreshName string `json:"cookie-refresh-name" yaml:"cookie-refresh-name"`
	// SecureCookie enforces the cookie as secure
	SecureCookie bool `json:"secure-cookie" yaml:"secure-cookie"`
	// IdleDuration is the max amount of time a session can last without being used
	IdleDuration time.Duration `json:"idle-duration" yaml:"idle-duration"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption-key" yaml:"encryption-key"`
	// MatchClaims is a series of checks, the claims in the token must match those here
	MatchClaims map[string]string `json:"match-claims" yaml:"match-claims"`
	// AddClaims is a series of claims that should be added to the auth headers
	AddClaims []string `json:"add-claims" yaml:"add-claims"`
	// UpstreamKeepalives specifies wheather we use keepalives on the upstream
	UpstreamKeepalives bool `json:"upstream-keepalives" yaml:"upstream-keepalives"`
	// Listen is the binding interface
	Listen string `json:"listen" yaml:"listen"`
	// ProxyProtocol enables proxy protocol
	ProxyProtocol bool `json:"proxy-protocol" yaml:"proxy-protocol"`
	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `json:"tls-cert" yaml:"tls-cert"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls-private-key" yaml:"tls-private-key"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `json:"tls-ca-certificate" yaml:"tls-ca-certificate"`
	// SkipUpstreamTLSVerify skips the verification of any upstream tls
	SkipUpstreamTLSVerify bool `json:"skip-upstream-tls-verify" yaml:"skip-upstream-tls-verify"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream-url" yaml:"upstream-url"`
	// TagData is passed to the templates
	TagData map[string]string `json:"tag-data" yaml:"tag-data"`
	// CrossOrigin permits adding headers to the /oauth handlers
	CrossOrigin CORS `json:"cors" yaml:"cors"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" yaml:"headers"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes"`
	// Resources is a list of protected resources
	Resources []*Resource `json:"resources" yaml:"resources"`
	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign-in-page" yaml:"sign-in-page"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `json:"forbidden-page" yaml:"forbidden-page"`
	// SkipTokenVerification tells the service to skipp verifying the access token - for testing purposes
	SkipTokenVerification bool `json:"skip-token-verification" yaml:"skip-token-verification"`
	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose"`
	// Hostname is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames"`
	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `json:"store-url" yaml:"store-url"`
}

// store is used to hold the offline refresh token, assuming you don't want to use
// the default practice of a encrypted cookie
type storage interface {
	// Add the token to the store
	Set(string, string) error
	// Get retrieves a token from the store
	Get(string) (string, error)
	// Delete removes a key from the store
	Delete(string) error
	// Close is used to close off any resources
	Close() error
}

// tokenResponse
type tokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

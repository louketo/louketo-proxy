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
	"net/http"
	"time"

	"github.com/coreos/go-oidc/jose"
)

var (
	release = "v2.1.0"
	gitsha  = "no gitsha provided"
	version = release + " (git+sha: " + gitsha + ")"
)

const (
	prog        = "keycloak-proxy"
	author      = "Rohith"
	email       = "gambol99@gmail.com"
	description = "is a proxy using the keycloak service for auth and authorization"
	httpSchema  = "http"

	headerUpgrade       = "Upgrade"
	userContextName     = "identity"
	revokeContextName   = "revoke"
	authorizationHeader = "Authorization"
	versionHeader       = "X-Auth-Proxy-Version"
	envPrefix           = "PROXY_"

	oauthURL         = "/oauth"
	authorizationURL = "/authorize"
	callbackURL      = "/callback"
	expiredURL       = "/expired"
	healthURL        = "/health"
	loginURL         = "/login"
	logoutURL        = "/logout"
	metricsURL       = "/metrics"
	tokenURL         = "/token"

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
	URL string `json:"uri" yaml:"uri"`
	// Methods the method type
	Methods []string `json:"methods" yaml:"methods"`
	// WhiteListed permits the prefix through
	WhiteListed bool `json:"white-listed" yaml:"white-listed"`
	// Roles the roles required to access this url
	Roles []string `json:"roles" yaml:"roles"`
}

// Config is the configuration for the proxy
type Config struct {
	// ConfigFile is the binding interface
	ConfigFile string `json:"config" yaml:"config" usage:"path the a configuration file" env:"CONFIG_FILE"`
	// Listen is the binding interface
	Listen string `json:"listen" yaml:"listen" usage:"the interface the service should be listening on" env:"LISTEN"`
	// ListenHTTP is the interface to bind the http only service on
	ListenHTTP string `json:"listen-http" yaml:"listen-http" usage:"interface we should be listening" env:"LISTEN_HTTP"`
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery-url" yaml:"discovery-url" usage:"discovery url to retrieve the openid configuration" env:"DISCOVERY_URL"`
	// ClientID is the client id
	ClientID string `json:"client-id" yaml:"client-id" usage:"client id used to authenticate to the oauth service" env:"CLIENT_ID"`
	// ClientSecret is the secret for AS
	ClientSecret string `json:"client-secret" yaml:"client-secret" usage:"client secret used to authenticate to the oauth service" env:"CLIENT_SECRET"`
	// RedirectionURL the redirection url
	RedirectionURL string `json:"redirection-url" yaml:"redirection-url" usage:"redirection url for the oauth callback url, defaults to host header is absent" env:"REDIRECTION_URL"`
	// RevocationEndpoint is the token revocation endpoint to revoke refresh tokens
	RevocationEndpoint string `json:"revocation-url" yaml:"revocation-url" usage:"url for the revocation endpoint to revoke refresh token" env:"REVOCATION_URL"`
	// SkipOpenIDProviderTLSVerify skips the tls verification for openid provider communication
	SkipOpenIDProviderTLSVerify bool `json:"skip-openid-provider-tls-verify" yaml:"skip-openid-provider-tls-verify" usage:"skip the verification of any TLS communication with the openid provider"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes" usage:"list of scopes requested when authenticating the user"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream-url" yaml:"upstream-url" usage:"url for the upstream endpoint you wish to proxy" env:"UPSTREAM_URL"`
	// Resources is a list of protected resources
	Resources []*Resource `json:"resources" yaml:"resources" usage:"list of resources 'uri=/admin|methods=GET,PUT|roles=role1,role2'"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" yaml:"headers" usage:"custom headers to the upstream request, key=value"`

	// EnableLogging indicates if we should log all the requests
	EnableLogging bool `json:"enable-logging" yaml:"enable-logging" usage:"enable http logging of the requests"`
	// EnableJSONLogging is the logging format
	EnableJSONLogging bool `json:"enable-json-logging" yaml:"enable-json-logging" usage:"switch on json logging rather than text"`
	// EnableForwarding enables the forwarding proxy
	EnableForwarding bool `json:"enable-forwarding" yaml:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request"`
	// EnableSecurityFilter enabled the security handler
	EnableSecurityFilter bool `json:"enable-security-filter" yaml:"enable-security-filter" usage:"enables the security filter handler"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `json:"enable-refresh-tokens" yaml:"enable-refresh-tokens" usage:"nables the handling of the refresh tokens" env:"ENABLE_SECURITY_FILTER"`
	// EnableLoginHandler indicates we want the login handler enabled
	EnableLoginHandler bool `json:"enable-login-handler" yaml:"enable-login-handler" usage:"enables the handling of the refresh tokens" env:"ENABLE_LOGIN_HANDLER"`
	// EnableAuthorizationHeader indicates we should pass the authorization header
	EnableAuthorizationHeader bool `json:"enable-authorization-header" yaml:"enable-authorization-header" usage:"adds the authorization header to the proxy request"`
	// EnableHTTPSRedirect indicate we should redirection http -> https
	EnableHTTPSRedirect bool `json:"enable-https-redirection" yaml:"enable-https-redirection" usage:"enable the http to https redirection on the http service"`
	// EnableProfiling indicates if profiles is switched on
	EnableProfiling bool `json:"enable-profiling" yaml:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc"`
	// EnableMetrics indicates if the metrics is enabled
	EnableMetrics bool `json:"enable-metrics" yaml:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics"`
	// EnableBrowserXSSFilter indicates you want the filter on
	EnableBrowserXSSFilter bool `json:"filter-browser-xss" yaml:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block"`
	// EnableContentNoSniff indicates you want the filter on
	EnableContentNoSniff bool `json:"filter-content-nosniff" yaml:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff"`
	// EnableFrameDeny indicates the filter is on
	EnableFrameDeny bool `json:"filter-frame-deny" yaml:"filter-frame-deny" usage:"enable to the frame deny header"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value
	ContentSecurityPolicy string `json:"content-security-policy" yaml:"content-security-policy" usage:"specify the content security policy"`
	// LocalhostMetrics indicated the metrics can only be consume via localhost
	LocalhostMetrics bool `json:"localhost-metrics" yaml:"localhost-metrics" usage:"enforces the metrics page can only been requested from 127.0.0.1"`

	// AccessTokenDuration is default duration applied to the access token cookie
	AccessTokenDuration time.Duration `json:"access-token-duration" yaml:"access-token-duration" usage:"fallback cookie duration for the access token when using refresh tokens"`
	// CookieDomain is a list of domains the cookie is available to
	CookieDomain string `json:"cookie-domain" yaml:"cookie-domain" usage:"domain the access cookie is available to, defaults host header"`
	// CookieAccessName is the name of the access cookie holding the access token
	CookieAccessName string `json:"cookie-access-name" yaml:"cookie-access-name" usage:"name of the cookie use to hold the access token"`
	// CookieRefreshName is the name of the refresh cookie
	CookieRefreshName string `json:"cookie-refresh-name" yaml:"cookie-refresh-name" usage:"name of the cookie used to hold the encrypted refresh token"`
	// SecureCookie enforces the cookie as secure
	SecureCookie bool `json:"secure-cookie" yaml:"secure-cookie" usage:"enforces the cookie to be secure"`
	// HTTPOnlyCookie enforces the cookie as http only
	HTTPOnlyCookie bool `json:"http-only-cookie" yaml:"http-only-cookie" usage:"enforces the cookie is in http only mode"`

	// MatchClaims is a series of checks, the claims in the token must match those here
	MatchClaims map[string]string `json:"match-claims" yaml:"match-claims" usage:"keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*"`
	// AddClaims is a series of claims that should be added to the auth headers
	AddClaims []string `json:"add-claims" yaml:"add-claims" usage:"extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name"`

	// TLSCertificate is the location for a tls certificate
	TLSCertificate string `json:"tls-cert" yaml:"tls-cert" usage:"path to ths TLS certificate"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls-private-key" yaml:"tls-private-key" usage:"path to the private key for TLS"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `json:"tls-ca-certificate" yaml:"tls-ca-certificate" usage:"path to the ca certificate used for signing requests"`
	// TLSCaPrivateKey is the CA private key used for signing
	TLSCaPrivateKey string `json:"tls-ca-key" yaml:"tls-ca-key" usage:"path the ca private key, used by the forward signing proxy"`
	// TLSClientCertificate is path to a client certificate to use for outbound connections
	TLSClientCertificate string `json:"tls-client-certificate" yaml:"tls-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes"`
	// SkipUpstreamTLSVerify skips the verification of any upstream tls
	SkipUpstreamTLSVerify bool `json:"skip-upstream-tls-verify" yaml:"skip-upstream-tls-verify" usage:"skip the verification of any upstream TLS"`

	// CorsOrigins is a list of origins permitted
	CorsOrigins []string `json:"cors-origins" yaml:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)"`
	// CorsMethods is a set of access control methods
	CorsMethods []string `json:"cors-methods" yaml:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)"`
	// CorsHeaders is a set of cors headers
	CorsHeaders []string `json:"cors-headers" yaml:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)"`
	// CorsExposedHeaders are the exposed header fields
	CorsExposedHeaders []string `json:"cors-exposed-headers" yaml:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)"`
	// CorsCredentials set the creds flag
	CorsCredentials bool `json:"cors-credentials" yaml:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)"`
	// CorsMaxAge is the age for CORS
	CorsMaxAge time.Duration `json:"cors-max-age" yaml:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)"`

	// Hostname is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames" usage:"list of hostnames the service will respond to"`

	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `json:"store-url" yaml:"store-url" usage:"url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption-key" yaml:"encryption-key" usage:"encryption key used to encryption the session state" env:"ENCRYPTION_KEY"`

	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `json:"no-redirects" yaml:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them"`
	// SkipTokenVerification tells the service to skipp verifying the access token - for testing purposes
	SkipTokenVerification bool `json:"skip-token-verification" yaml:"skip-token-verification" usage:"TESTING ONLY; bypass token verification, only expiration and roles enforced"`
	// UpstreamKeepalives specifies whether we use keepalives on the upstream
	UpstreamKeepalives bool `json:"upstream-keepalives" yaml:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint"`
	// UpstreamTimeout is the maximum amount of time a dial will wait for a connect to complete
	UpstreamTimeout time.Duration `json:"upstream-timeout" yaml:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete"`
	// UpstreamKeepaliveTimeout
	UpstreamKeepaliveTimeout time.Duration `json:"upstream-keepalive-timeout" yaml:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection"`
	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose" usage:"switch on debug / verbose logging"`
	// EnableProxyProtocol controls the proxy protocol
	EnableProxyProtocol bool `json:"enabled-proxy-protocol" yaml:"enabled-proxy-protocol" usage:"enable proxy protocol"`

	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign-in-page" yaml:"sign-in-page" usage:"path to custom template displayed for signin"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `json:"forbidden-page" yaml:"forbidden-page" usage:"path to custom template used for access forbidden"`
	// Tags is passed to the templates
	Tags map[string]string `json:"tags" yaml:"tags" usage:"keypairs passed to the templates at render,e.g title=Page"`

	// ForwardingUsername is the username to login to the oauth service
	ForwardingUsername string `json:"forwarding-username" yaml:"forwarding-username" usage:"username to use when logging into the openid provider"`
	// ForwardingPassword is the password to use for the above
	ForwardingPassword string `json:"forwarding-password" yaml:"forwarding-password" usage:"password to use when logging into the openid provider"`
	// ForwardingDomains is a collection of domains to signs
	ForwardingDomains []string `json:"forwarding-domains" yaml:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned"`
}

// storage is used to hold the offline refresh token, assuming you don't want to use
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

// reverseProxy is a wrapper
type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
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
	// the audience for the token
	audience string
	// the access token itself
	token jose.JWT
	// the claims associated to the token
	claims jose.Claims
	// whether the context is from a session cookie or authorization header
	bearerToken bool
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

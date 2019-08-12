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

/*
Package main provides a transparent authentication proxy suited for use with Keycloak as OIDC identity provider
*/
package main

import (
	"net/http"
	"time"

	"github.com/coreos/go-oidc/jose"
)

type contextKey int8

const (
	envPrefix = "PROXY_"

	// defaults proxy endpoints
	authorizationURL = "/authorize"
	callbackURL      = "/callback"
	expiredURL       = "/expired"
	healthURL        = "/health"
	loginURL         = "/login"
	logoutURL        = "/logout"
	metricsURL       = "/metrics"
	tokenURL         = "/token"
	debugURL         = "/debug/pprof"
	refreshURL       = "/refresh"
	traceURL         = "/trace"

	// default claims used to analyze access token
	claimAudience       = "aud"
	claimPreferredName  = "preferred_username"
	claimRealmAccess    = "realm_access"
	claimResourceAccess = "resource_access"
	claimResourceRoles  = "roles"
	claimGroups         = "groups"

	// default cookies names
	accessCookie       = "kc-access"
	refreshCookie      = "kc-state"
	requestURICookie   = "request_uri"
	requestStateCookie = "OAuth_Token_Request_State"

	unsecureScheme = "http"
	secureScheme   = "https"
	anyMethod      = "ANY"
	allRoutes      = "/*"

	_ contextKey = iota
	contextScopeName

	jsonMime            = "application/json; charset=utf-8"
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
	authorizationHeader = "Authorization"
	//headerUpgrade       = "Upgrade"
	versionHeader = "X-Auth-Proxy-Version"
)

// Config is the configuration for the proxy
type Config struct {
	// ConfigFile is the binding interface
	ConfigFile string `json:"config" yaml:"config" usage:"path the a configuration file" env:"CONFIG_FILE"`
	// Listen defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value.
	Listen string `json:"listen" yaml:"listen" usage:"Defines the binding interface for main listener, e.g. {address}:{port}. This is required and there is no default value" env:"LISTEN"`
	// ListenHTTP is the interface to bind the http only service on
	ListenHTTP string `json:"listen-http" yaml:"listen-http" usage:"interface we should be listening to for HTTP traffic" env:"LISTEN_HTTP"`
	// ListenAdmin defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen.
	ListenAdmin string `json:"listen-admin" yaml:"listen-admin" usage:"defines the interface to bind admin-only endpoint (live-status, debug, prometheus...). If not defined, this defaults to the main listener defined by Listen" env:"LISTEN_ADMIN"`
	// ListenAdminScheme defines the scheme admin endpoints are served with. If not defined, same as main listener.
	ListenAdminScheme string `json:"listen-admin-scheme" yaml:"listen-admin-scheme" usage:"scheme to serve admin-only endpoint (http or https)." env:"LISTEN_ADMIN_SCHEME"`
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
	// OpenIDProviderProxy proxy for openid provider communication
	OpenIDProviderProxy string `json:"openid-provider-proxy" yaml:"openid-provider-proxy" usage:"proxy for communication with the openid provider"`
	// OpenIDProviderTimeout is the timeout used to pulling the openid configuration from the provider
	OpenIDProviderTimeout time.Duration `json:"openid-provider-timeout" yaml:"openid-provider-timeout" usage:"timeout for openid configuration on .well-known/openid-configuration"`
	// OpenIDProviderCA is the certificate authority issuing the TLS certificate for the OpenID provider
	OpenIDProviderCA string `json:"openid-provider-ca" yaml:"openid-provider-ca" usage:"certificate authority for openid configuration endpoints"`
	// BaseURI is prepended to all the generated URIs
	BaseURI string `json:"base-uri" yaml:"base-uri" usage:"common prefix for all URIs" env:"BASE_URI"`
	// OAuthURI is the uri for the oauth endpoints for the proxy
	OAuthURI string `json:"oauth-uri" yaml:"oauth-uri" usage:"the uri for proxy oauth endpoints" env:"OAUTH_URI"`
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes" usage:"list of scopes requested when authenticating the user"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream-url" yaml:"upstream-url" usage:"url for the upstream endpoint you wish to proxy" env:"UPSTREAM_URL"`
	// UpstreamCA is the path to a CA certificate in PEM format to validate the upstream certificate
	UpstreamCA string `json:"upstream-ca" yaml:"upstream-ca" usage:"the path to a file container a CA certificate to validate the upstream tls endpoint" env:"UPSTREAM_CA"`
	// Resources is a list of protected resources
	Resources []*Resource `json:"resources" yaml:"resources" usage:"list of resources 'uri=/admin*|methods=GET,PUT|roles=role1,role2'"`
	// Headers permits adding customs headers across the board
	Headers map[string]string `json:"headers" yaml:"headers" usage:"custom headers to the upstream request, key=value"`
	// PreserveHost preserves the host header of the proxied request in the upstream request
	PreserveHost bool `json:"preserve-host" yaml:"preserve-host" usage:"preserve the host header of the proxied request in the upstream request"`
	// RequestIDHeader is the header name for request ids
	RequestIDHeader string `json:"request-id-header" yaml:"request-id-header" usage:"the http header name for request id" env:"REQUEST_ID_HEADER"`
	// ResponseHeader is a map of response headers to add to the response
	ResponseHeaders map[string]string `json:"response-headers" yaml:"response-headers" usage:"custom headers to be added to the http response key=value"`

	// EnableSelfSignedTLS indicates we should create a self-signed certificate for the service
	EnabledSelfSignedTLS bool `json:"enable-self-signed-tls" yaml:"enable-self-signed-tls" usage:"create self signed certificates for the proxy" env:"ENABLE_SELF_SIGNED_TLS"`
	// SelfSignedTLSHostnames is the list of hostnames to place on the certificate
	SelfSignedTLSHostnames []string `json:"self-signed-tls-hostnames" yaml:"self-signed-tls-hostnames" usage:"a list of hostnames to place on the self-signed certificate"`
	// SelfSignedTLSExpiration is the expiration time of the tls certificate before rotation occurs
	SelfSignedTLSExpiration time.Duration `json:"self-signed-tls-expiration" yaml:"self-signed-tls-expiration" usage:"the expiration of the certificate before rotation"`

	// EnableRequestID indicates the proxy should add request id if none if found
	EnableRequestID bool `json:"enable-request-id" yaml:"enable-request-id" usage:"indicates we should add a request id if none found" env:"ENABLE_REQUEST_ID"`
	// EnableLogoutRedirect indicates we should redirect to the identity provider for logging out
	EnableLogoutRedirect bool `json:"enable-logout-redirect" yaml:"enable-logout-redirect" usage:"indicates we should redirect to the identity provider for logging out"`
	// EnableDefaultDeny indicates we should deny by default all requests
	EnableDefaultDeny bool `json:"enable-default-deny" yaml:"enable-default-deny" usage:"enables a default denial on all requests, you have to explicitly say what is permitted (recommended)" env:"ENABLE_DEFAULT_DENY"`
	// EnableDefaultNotFound: makes explicit resources routing mandatory (i.e. responds with 404 NotFound, even if authenticated)
	EnableDefaultNotFound bool `json:"enable-default-notfound" yaml:"enable-default-notfound" usage:"makes explicit resources routing mandatory (i.e. responds with 404 NotFound, even if authenticated)" env:"ENABLE_DEFAULT_NOTFOUND"`
	// EnableEncryptedToken indicates the access token should be encoded
	EnableEncryptedToken bool `json:"enable-encrypted-token" yaml:"enable-encrypted-token" usage:"enable encryption for the access tokens"`
	// ForceEncryptedCookie indicates that the access token in the cookie should be encoded, regardless what EnableEncryptedToken says. This way, gatekeeper may receive tokens in header in the clear, whereas tokens in cookies remain encrypted
	ForceEncryptedCookie bool `json:"force-encrypted-cookie" yaml:"force-encrypted-cookie" usage:"force encryption for the access tokens in cookies"`
	// EnableLogging indicates if we should log all the requests
	EnableLogging bool `json:"enable-logging" yaml:"enable-logging" usage:"enable http logging of the requests"`
	// EnableJSONLogging is the logging format
	EnableJSONLogging bool `json:"enable-json-logging" yaml:"enable-json-logging" usage:"switch on json logging rather than text"`
	// EnableForwarding enables the forwarding proxy
	EnableForwarding bool `json:"enable-forwarding" yaml:"enable-forwarding" usage:"enables the forwarding proxy mode, signing outbound request"`
	// EnableSecurityFilter enables the security handler
	EnableSecurityFilter bool `json:"enable-security-filter" yaml:"enable-security-filter" usage:"enables the security filter handler" env:"ENABLE_SECURITY_FILTER"`
	// EnableRefreshTokens indicate's you wish to ignore using refresh tokens and re-auth on expiration of access token
	EnableRefreshTokens bool `json:"enable-refresh-tokens" yaml:"enable-refresh-tokens" usage:"enables the handling of the refresh tokens" env:"ENABLE_REFRESH_TOKEN"`
	// EnableSessionCookies indicates the cookies, both token and refresh should not be persisted
	EnableSessionCookies bool `json:"enable-session-cookies" yaml:"enable-session-cookies" usage:"access and refresh tokens are session only i.e. removed browser close" env:"ENABLE_SESSION_COOKIES"`
	// EnableCSRF will generate a new session object (e.g.a cookie, or in a supported backend storage) to store a CSRF token.
	// To enable CSRF on upstream endpoints, an additional EnableCSRF is needed in the Resource config section.
	EnableCSRF bool `json:"enable-csrf" yaml:"enable-csrf" usage:"when enabled, this automatically adds a CSRF token to all responses. Matching token expected for next request is stored in the session (e.g. cookie or storage)" env:"ENABLE_CSRF"`
	// CSRFCookieName sets the name of the CSRF (encrypted) cookie, when session storage is a cookie (defaults to kc-csrf).
	// Note that in this case EncryptionKey is required to encrypt the cookie.
	CSRFCookieName string `json:"csrf-cookie-name" yaml:"csrf-cookie-name" usage:"the name of CSRF cookie. Defaults to: kc-csrf" env:"CSRF_COOKIE_NAME"`
	// CSRFHeader sets the header used in requests and response for the CSRF challenge (defaults to X-CSRF-Token)
	CSRFHeader string `json:"csrf-header" yaml:"csrf-header" usage:"the header added to responses by gatekeeper and to be added by requests to check against replayed credentials (CSRF). Defaults to: X-CSRF-Token" env:"CSRF_HEADER"`
	// EnableLoginHandler indicates we want the login handler enabled
	EnableLoginHandler bool `json:"enable-login-handler" yaml:"enable-login-handler" usage:"enables the handling of the refresh tokens" env:"ENABLE_LOGIN_HANDLER"`
	// EnableTokenHeader adds the JWT token to the upstream authentication headers as X-Auth-Token header
	EnableTokenHeader bool `json:"enable-token-header" yaml:"enable-token-header" usage:"enables the token authentication header X-Auth-Token to upstream" env:"ENABLE_TOKEN_HEADER"`
	// EnableClaimsHeaders adds decoded claims as headers X-Auth-{claim} to the upstream endpoint
	EnableClaimsHeaders bool `json:"enable-claims-headers" yaml:"enable-claims-headers" usage:"adds decoded claims as headers X-Auth-{claim} to the upstream endpoint. Defaults to true" env:"ENABLE_CLAIMS_HEADERS"`
	// EnableAuthorizationHeader indicates we should pass the authorization header to the upstream endpoint
	EnableAuthorizationHeader bool `json:"enable-authorization-header" yaml:"enable-authorization-header" usage:"adds the authorization header to the proxy request" env:"ENABLE_AUTHORIZATION_HEADER"`
	// EnableAuthorizationCookies indicates we should pass the authorization cookies to the upstream endpoint
	EnableAuthorizationCookies bool `json:"enable-authorization-cookies" yaml:"enable-authorization-cookies" usage:"adds the authorization cookies to the uptream proxy request" env:"ENABLE_AUTHORIZATION_COOKIES"`
	// EnableHTTPSRedirect indicate we should redirect http -> https
	EnableHTTPSRedirect bool `json:"enable-https-redirection" yaml:"enable-https-redirection" usage:"enable the http to https redirection on the http service"`
	// EnableProfiling indicates if profiles is switched on
	EnableProfiling bool `json:"enable-profiling" yaml:"enable-profiling" usage:"switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc" env:"ENABLE_PROFILING"`
	// EnableMetrics indicates if the metrics is enabled (default: true)
	EnableMetrics bool `json:"enable-metrics" yaml:"enable-metrics" usage:"enable the prometheus metrics collector on /oauth/metrics (enabled by default)" env:"ENABLE_METRICS"`
	// EnableTracing indicates if a tracing exporter is enabled
	EnableTracing bool `json:"enable-tracing" yaml:"enable-tracing" usage:"enable the opencensus trace collector on /oauth/zpages" env:"ENABLE_TRACING"`
	// TracingAgentEndpoint register the jaeger agent collecting trace spans
	TracingAgentEndpoint string `json:"tracing-agent-endpoint" yaml:"tracing-agent-endpoint" usage:"register the opencensus trace collector agent" env:"TRACING_AGENT_ENDPOINT"`
	// EnableBrowserXSSFilter indicates you want the filter on
	EnableBrowserXSSFilter bool `json:"filter-browser-xss" yaml:"filter-browser-xss" usage:"enable the adds the X-XSS-Protection header with mode=block"`
	// EnableContentNoSniff indicates you want the filter on
	EnableContentNoSniff bool `json:"filter-content-nosniff" yaml:"filter-content-nosniff" usage:"adds the X-Content-Type-Options header with the value nosniff"`
	// EnableFrameDeny indicates the filter is on
	EnableFrameDeny bool `json:"filter-frame-deny" yaml:"filter-frame-deny" usage:"enable to the frame deny header"`
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value
	ContentSecurityPolicy string `json:"content-security-policy" yaml:"content-security-policy" usage:"specify the content security policy"`
	// LocalhostMetrics indicates that metrics can only be consumed from localhost
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
	TLSCertificate string `json:"tls-cert" yaml:"tls-cert" usage:"path to ths TLS certificate" env:"TLS_CERTIFICATE"`
	// TLSPrivateKey is the location of a tls private key
	TLSPrivateKey string `json:"tls-private-key" yaml:"tls-private-key" usage:"path to the private key for TLS" env:"TLS_PRIVATE_KEY"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSCaCertificate string `json:"tls-ca-certificate" yaml:"tls-ca-certificate" usage:"path to the ca certificate used for signing requests" env:"TLS_CA_CERTIFICATE"`
	// TLSCaPrivateKey is the CA private key used for signing
	TLSCaPrivateKey string `json:"tls-ca-key" yaml:"tls-ca-key" usage:"path the ca private key, used by the forward signing proxy" env:"TLS_CA_PRIVATE_KEY"`
	// TLSClientCertificate is path to a client certificate to use for outbound connections
	TLSClientCertificate string `json:"tls-client-certificate" yaml:"tls-client-certificate" usage:"path to the client certificate for outbound connections in reverse and forwarding proxy modes" env:"TLS_CLIENT_CERTIFICATE"`
	// TLSClientCertificates is an array of paths to client certificates to use for outbound connections
	TLSClientCertificates []string `json:"tls-client-certificates" yaml:"tls-client-certificates" usage:"paths to client certificates for outbound connections in reverse and forwarding proxy modes" env:"TLS_CLIENT_CERTIFICATES"`
	// TLSUseModernSettings sets all TLS options for proxy listener to modern settings (TLS 1.2, advanced cipher suites, ...)
	TLSUseModernSettings bool `json:"tls-use-modern-settings" yaml:"tls-use-modern-settings" usage:"sets all TLS options for proxy listener to modern settings (TLS 1.2, advanced cipher suites, ...)" env:"TLS_USE_MODERN_SETTINGS"`
	// TLSMinVersion is the minimum TLS protocol version accepted by proxy listener. TLS 1.0 is the default.
	TLSMinVersion string `json:"tls-min-version" yaml:"tls-min-version" usage:"the minimum TLS protocol version accepted by proxy listener. Accepted values are: SSL3.0, TLS1.0, TLS1.1, TLS1.2. TLS1.0 is the default" env:"TLS_MIN_VERSION"`
	// TLSCipherSuites is the list of cipher suites accepted by server during TLS negotiation. Defaults to golang TLS supported suites.
	TLSCipherSuites []string `json:"tls-cipher-suites" yaml:"tls-cipher-suites" usage:"the list of cipher suites accepted by server during TLS negotiation. Defaults to golang TLS supported suites" env:"TLS_CIPHER_SUITES"`
	// TLSPreferServerCipherSuites indicates the TLS negotiation prefers server cipher suites
	TLSPreferServerCipherSuites bool `json:"tls-prefer-server-cipher-suites" yaml:"tls-prefer-server-cipher-suites" usage:"indicates the TLS negotiation prefers server cipher suites" env:"TLS_PREFER_SERVER_CIPHER_SUITES"`
	// TLSCurvePreferences indicate the server preferred cipher curves
	TLSCurvePreferences []string `json:"tls-curve-preferences" yaml:"tls-curve-preferences" usage:"the server preferred cipher curves" env:"TLS_CURVE_PREFERENCES"`
	// SkipUpstreamTLSVerify skips the verification of any upstream tls
	SkipUpstreamTLSVerify bool `json:"skip-upstream-tls-verify" yaml:"skip-upstream-tls-verify" usage:"skip the verification of any upstream TLS" env:"SKIP_UPSTREAM_TLS_VERIFY"`

	// TLSAdminCertificate is the location for a tls certificate for admin https endpoint. Defaults to TLSCertificate.
	TLSAdminCertificate string `json:"tls-admin-cert" yaml:"tls-admin-cert" usage:"path to ths TLS certificate" env:"TLS_ADMIN_CERTIFICATE"`
	// TLSAdminPrivateKey is the location of a tls private key for admin https endpoint. Defaults to TLSPrivateKey
	TLSAdminPrivateKey string `json:"tls-admin-private-key" yaml:"tls-admin-private-key" usage:"path to the private key for TLS" env:"TLS_ADMIN_PRIVATE_KEY"`
	// TLSCaCertificate is the CA certificate which the client cert must be signed
	TLSAdminCaCertificate string `json:"tls-admin-ca-certificate" yaml:"tls-admin-ca-certificate" usage:"path to the ca certificate used for signing requests" env:"TLS_ADMIN_CA_CERTIFICATE"`
	// TLSAdminClientCertificate is path to a client certificate to use for admin endpoint
	TLSAdminClientCertificate string `json:"tls-admin-client-certificate" yaml:"tls-admin-client-certificate" usage:"path to the client certificate for admin endpoint" env:"TLS_ADMIN_CLIENT_CERTIFICATE"`
	// TLSAdminClientCertificates is an array of paths to client certificates to use for admin endpoint
	TLSAdminClientCertificates []string `json:"tls-admin-client-certificates" yaml:"tls-admin-client-certificates" usage:"paths to client certificates for admin endpoint" env:"TLS_ADMIN_CLIENT_CERTIFICATES"`

	// CorsOrigins is a list of origins permitted
	CorsOrigins []string `json:"cors-origins" yaml:"cors-origins" usage:"origins to add to the CORE origins control (Access-Control-Allow-Origin)"`
	// CorsMethods is a set of access control methods
	CorsMethods []string `json:"cors-methods" yaml:"cors-methods" usage:"methods permitted in the access control (Access-Control-Allow-Methods)"`
	// CorsHeaders is a set of cors headers
	CorsHeaders []string `json:"cors-headers" yaml:"cors-headers" usage:"set of headers to add to the CORS access control (Access-Control-Allow-Headers)"`
	// CorsExposedHeaders are the exposed header fields
	CorsExposedHeaders []string `json:"cors-exposed-headers" yaml:"cors-exposed-headers" usage:"expose cors headers access control (Access-Control-Expose-Headers)"`
	// CorsCredentials set the credentials flag
	CorsCredentials bool `json:"cors-credentials" yaml:"cors-credentials" usage:"credentials access control header (Access-Control-Allow-Credentials)"`
	// CorsMaxAge is the age for CORS
	CorsMaxAge time.Duration `json:"cors-max-age" yaml:"cors-max-age" usage:"max age applied to cors headers (Access-Control-Max-Age)"`
	// CorsDisableUpstream disables CORS headers prepared by the gatekeeper from the relayed upstream response (deprecated)
	CorsDisableUpstream bool `json:"cors-disable-upstream" yaml:"cors-disable-upstream" usage:"Deprecated: do not extend CORS support to upstream responses: only gatekeeper endpoints are CORS-enabled"`

	// Hostnames is a list of hostname's the service should response to
	Hostnames []string `json:"hostnames" yaml:"hostnames" usage:"list of hostnames the service will respond to"`

	// Store is a url for a store resource, used to hold the refresh tokens
	StoreURL string `json:"store-url" yaml:"store-url" usage:"url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file"`

	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption-key" yaml:"encryption-key" usage:"encryption key used to encryption the session state" env:"ENCRYPTION_KEY"`

	// InvalidAuthRedirectsWith303 will make requests with invalid auth headers redirect using HTTP 303 instead of HTTP 307.  See github.com/keycloak/keycloak-gatekeeper/issues/292 for context.
	InvalidAuthRedirectsWith303 bool `json:"invalid-auth-redirects-with-303" yaml:"invalid-auth-redirects-with-303" usage:"use HTTP 303 redirects instead of 307 for invalid auth tokens"`
	// NoRedirects informs we should hand back a 401 not a redirect
	NoRedirects bool `json:"no-redirects" yaml:"no-redirects" usage:"do not have back redirects when no authentication is present, 401 them"`

	// SkipTokenVerification tells the service to skip verifying the access token - for testing purposes
	SkipTokenVerification bool `json:"skip-token-verification" yaml:"skip-token-verification" usage:"TESTING ONLY; bypass token verification, only expiration and roles enforced"`

	// UpstreamKeepalives specifies whether we use keepalives on the upstream
	UpstreamKeepalives bool `json:"upstream-keepalives" yaml:"upstream-keepalives" usage:"enables or disables the keepalive connections for upstream endpoint"`
	// UpstreamTimeout is the maximum amount of time a dial will wait for a connect to complete. Defaults to 10s
	UpstreamTimeout time.Duration `json:"upstream-timeout" yaml:"upstream-timeout" usage:"maximum amount of time a dial will wait for a connect to complete. Defaults to 10s" env:"UPSTREAM_TIMEOUT"`
	// UpstreamKeepaliveTimeout is the upstream keepalive timeout. Defaults to 10s
	UpstreamKeepaliveTimeout time.Duration `json:"upstream-keepalive-timeout" yaml:"upstream-keepalive-timeout" usage:"specifies the keep-alive period for an active network connection. Defaults to 10s" env:"UPSTREAM_KEEPALIVE_TIMEOUT"`
	// UpstreamTLSHandshakeTimeout is the timeout for upstream to tls handshake
	UpstreamTLSHandshakeTimeout time.Duration `json:"upstream-tls-handshake-timeout" yaml:"upstream-tls-handshake-timeout" usage:"the timeout placed on the tls handshake for upstream"`
	// UpstreamResponseHeaderTimeout is the timeout for upstream header response
	UpstreamResponseHeaderTimeout time.Duration `json:"upstream-response-header-timeout" yaml:"upstream-response-header-timeout" usage:"the timeout placed on the response header for upstream"`
	// UpstreamExpectContinueTimeout is the timeout expect continue for upstream
	UpstreamExpectContinueTimeout time.Duration `json:"upstream-expect-continue-timeout" yaml:"upstream-expect-continue-timeout" usage:"the timeout placed on the expect continue for upstream"`

	// Verbose switches on debug logging
	Verbose bool `json:"verbose" yaml:"verbose" usage:"switch on debug / verbose logging"`
	// EnableProxyProtocol controls the proxy protocol
	EnableProxyProtocol bool `json:"enabled-proxy-protocol" yaml:"enabled-proxy-protocol" usage:"enable proxy protocol"`

	// MaxIdleConns is the max idle connections to keep alive, ready for reuse
	MaxIdleConns int `json:"max-idle-connections" yaml:"max-idle-connections" usage:"max idle upstream / keycloak connections to keep alive, ready for reuse"`
	// MaxIdleConnsPerHost limits the number of idle connections maintained per host
	MaxIdleConnsPerHost int `json:"max-idle-connections-per-host" yaml:"max-idle-connections-per-host" usage:"limits the number of idle connections maintained per host"`

	// ServerReadTimeout is the read timeout on the http server
	ServerReadTimeout time.Duration `json:"server-read-timeout" yaml:"server-read-timeout" usage:"the server read timeout on the http server"`
	// ServerWriteTimeout is the write timeout on the http server. Defaults to 11s (should be larger than UpstreamTimeout)
	ServerWriteTimeout time.Duration `json:"server-write-timeout" yaml:"server-write-timeout" usage:"the server write timeout on the http server"`
	// ServerIdleTimeout is the idle timeout on the http server
	ServerIdleTimeout time.Duration `json:"server-idle-timeout" yaml:"server-idle-timeout" usage:"the server idle timeout on the http server" env:"SERVER_IDLE_TIMEOUT"`

	// UseLetsEncrypt controls if we should use letsencrypt to retrieve certificates
	UseLetsEncrypt bool `json:"use-letsencrypt" yaml:"use-letsencrypt" usage:"use letsencrypt for certificates"`

	// LetsEncryptCacheDir is the path to store letsencrypt certificates
	LetsEncryptCacheDir string `json:"letsencrypt-cache-dir" yaml:"letsencrypt-cache-dir" usage:"path where cached letsencrypt certificates are stored"`

	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign-in-page" yaml:"sign-in-page" usage:"path to custom template displayed for signin"`
	// ForbiddenPage is a access forbidden page
	ForbiddenPage string `json:"forbidden-page" yaml:"forbidden-page" usage:"path to custom template used for access forbidden"`
	// Tags is passed to the templates
	Tags map[string]string `json:"tags" yaml:"tags" usage:"keypairs passed to the templates at render,e.g title=Page"`

	// ForwardingUsername is the username to login to the oauth service
	ForwardingUsername string `json:"forwarding-username" yaml:"forwarding-username" usage:"username to use when logging into the openid provider" env:"FORWARDING_USERNAME"`
	// ForwardingPassword is the password to use for the above
	ForwardingPassword string `json:"forwarding-password" yaml:"forwarding-password" usage:"password to use when logging into the openid provider" env:"FORWARDING_PASSWORD"`
	// ForwardingDomains is a collection of domains to signs
	ForwardingDomains []string `json:"forwarding-domains" yaml:"forwarding-domains" usage:"list of domains which should be signed; everything else is relayed unsigned"`

	// DisableAllLogging indicates no logging at all
	DisableAllLogging bool `json:"disable-all-logging" yaml:"disable-all-logging" usage:"disables all logging to stdout and stderr"`
}

// RequestScope is a request level context scope passed between middleware
type RequestScope struct {
	// AccessDenied indicates the request should not be proxied on
	AccessDenied bool
	// Identity is the user Identity of the request
	Identity *userContext
}

// storage is used to hold the offline refresh token, assuming you don't want to use
// the default practice of a encrypted cookie
type storage interface {
	// Set the token to the store
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

// userContext holds the information extracted the token
type userContext struct {
	// the id of the user
	id string
	// the audience for the token
	audiences []string
	// whether the context is from a session cookie or authorization header
	bearerToken bool
	// the claims associated to the token
	claims jose.Claims
	// the email associated to the user
	email string
	// the expiration of the access token
	expiresAt time.Time
	// groups is a collection of groups the user in in
	groups []string
	// a name of the user
	name string
	// preferredName is the name of the user
	preferredName string
	// roles is a collection of roles the users holds
	roles []string
	// the access token itself
	token jose.JWT
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

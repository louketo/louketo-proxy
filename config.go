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
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// newDefaultConfig returns a initialized config
func newDefaultConfig() *Config {
	var hostnames []string
	if name, err := os.Hostname(); err == nil {
		hostnames = append(hostnames, name)
	}
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1", "::1"}...)

	return &Config{
		AccessTokenDuration:           time.Duration(720) * time.Hour,
		CookieAccessName:              accessCookie,
		CookieRefreshName:             refreshCookie,
		CSRFCookieName:                "kc-csrf",
		CSRFHeader:                    "X-Csrf-Token",
		EnableAuthorizationCookies:    false,
		EnableAuthorizationHeader:     true,
		EnableCSRF:                    false,
		EnableDefaultDeny:             true,
		EnableSessionCookies:          true,
		EnableTokenHeader:             true,
		EnableClaimsHeaders:           true,
		EnableMetrics:                 true,
		TracingExporter:               "jaeger",
		HTTPOnlyCookie:                true,
		Headers:                       make(map[string]string),
		LetsEncryptCacheDir:           "./cache/",
		MatchClaims:                   make(map[string]string),
		MaxIdleConns:                  100,
		MaxIdleConnsPerHost:           50,
		OAuthURI:                      "/oauth",
		OpenIDProviderTimeout:         30 * time.Second,
		PreserveHost:                  false,
		SelfSignedTLSExpiration:       3 * time.Hour,
		SelfSignedTLSHostnames:        hostnames,
		RequestIDHeader:               "X-Request-ID",
		ResponseHeaders:               make(map[string]string),
		SameSiteCookie:                SameSiteLax,
		SecureCookie:                  true,
		ServerIdleTimeout:             120 * time.Second,
		ServerReadTimeout:             10 * time.Second,
		ServerWriteTimeout:            11 * time.Second, // make it upstream timeout + 1s to avoid closing the connection before headers are sent
		SkipOpenIDProviderTLSVerify:   false,
		SkipUpstreamTLSVerify:         true,
		Tags:                          make(map[string]string),
		UpstreamExpectContinueTimeout: 10 * time.Second,
		UpstreamKeepaliveTimeout:      10 * time.Second,
		UpstreamKeepalives:            true,
		UpstreamResponseHeaderTimeout: 10 * time.Second,
		UpstreamTLSHandshakeTimeout:   10 * time.Second,
		UpstreamTimeout:               10 * time.Second,
		UseLetsEncrypt:                false,
	}
}

// WithOAuthURI returns the oauth uri
func (r *Config) WithOAuthURI(uri string) string {
	if r.BaseURI != "" {
		return fmt.Sprintf("%s/%s/%s", r.BaseURI, r.OAuthURI, uri)
	}

	return fmt.Sprintf("%s/%s", r.OAuthURI, uri)
}

// isValid validates if the config is valid
func (r *Config) isValid() error {
	if err := r.isListenValid(); err != nil {
		return err
	}
	if err := r.isTLSValid(); err != nil {
		return err
	}

	if r.UseLetsEncrypt && r.LetsEncryptCacheDir == "" {
		return fmt.Errorf("the letsencrypt cache dir has not been set")
	}

	if r.EnableForwarding {
		return r.isForwardingValid()
	}

	if r.EnableTracing && r.TracingAgentEndpoint == "" {
		return fmt.Errorf("an agent endpoint must be specified when enabling tracing")
	}
	const (
		jaegerExporter  = "jaeger"
		datadogExporter = "datadog"
	)
	if r.EnableTracing && r.TracingExporter != jaegerExporter && r.TracingExporter != datadogExporter {
		return fmt.Errorf("unsupported trace exporter. Current supported values are %q|%q", jaegerExporter, datadogExporter)
	}

	if r.SameSiteCookie != "" && r.SameSiteCookie != SameSiteStrict && r.SameSiteCookie != SameSiteLax && r.SameSiteCookie != SameSiteNone {
		return errors.New("same-site-cookie must be one of Strict|Lax|None")
	}

	return r.isReverseProxyValid()
}

// hasCustomSignInPage checks if there is a custom sign in  page
func (r *Config) hasCustomSignInPage() bool {
	return r.SignInPage != ""
}

// hasForbiddenPage checks if there is a custom forbidden page
func (r *Config) hasCustomForbiddenPage() bool {
	return r.ForbiddenPage != ""
}

// tlsAdvancedConfig holds advanced parameters to control TLS negotiation
type tlsAdvancedConfig struct {
	tlsUseModernSettings        bool
	tlsPreferServerCipherSuites bool
	tlsMinVersion               string
	tlsCipherSuites             []string
	tlsCurvePreferences         []string
}

// tlsSettings holds advanced TLS parameters, parsed from config
type tlsSettings struct {
	tlsPreferServerCipherSuites bool
	tlsMinVersion               uint16
	tlsCipherSuites             []uint16
	tlsCurvePreferences         []tls.CurveID
}

func parseTLS(config *tlsAdvancedConfig) (*tlsSettings, error) {
	parsed := &tlsSettings{}

	parsed.tlsPreferServerCipherSuites = config.tlsPreferServerCipherSuites || config.tlsUseModernSettings

	if config.tlsMinVersion != "" {
		switch config.tlsMinVersion {
		case "TLS1.0":
			parsed.tlsMinVersion = tls.VersionTLS10
		case "TLS1.1":
			parsed.tlsMinVersion = tls.VersionTLS11
		case "TLS1.2":
			parsed.tlsMinVersion = tls.VersionTLS12
		case "TLS1.3":
			parsed.tlsMinVersion = tls.VersionTLS13
		default:
			return nil, errors.New("invalid TLS version configured. Accepted values are: TLS1.0, TLS1.1, TLS1.2, TLS.1.3")
		}
	} else if config.tlsUseModernSettings {
		// standard modern setting
		// https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Rule_-_Only_Support_Strong_Protocols
		parsed.tlsMinVersion = tls.VersionTLS12
	}

	if config.tlsUseModernSettings || len(config.tlsCurvePreferences) > 0 {
		if len(config.tlsCurvePreferences) > 0 {
			parsed.tlsCurvePreferences = make([]tls.CurveID, 0, len(config.tlsCurvePreferences))
			for _, curveName := range config.tlsCurvePreferences {
				switch curveName {
				case "P256":
					parsed.tlsCurvePreferences = append(parsed.tlsCurvePreferences, tls.CurveP256)
				case "P384":
					parsed.tlsCurvePreferences = append(parsed.tlsCurvePreferences, tls.CurveP384)
				case "P521":
					parsed.tlsCurvePreferences = append(parsed.tlsCurvePreferences, tls.CurveP521)
				case "X25519":
					parsed.tlsCurvePreferences = append(parsed.tlsCurvePreferences, tls.X25519)
				default:
					return nil, errors.New("invalid TLS curve configured. Accepted values are: P256, P384, P521, X25519")
				}
			}
		} else if config.tlsUseModernSettings {
			// standard modern settings
			// Only use curves which have assembly implementations
			// https://github.com/golang/go/tree/master/src/crypto/elliptic
			parsed.tlsCurvePreferences = []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			}
		}
	}

	if config.tlsUseModernSettings || len(config.tlsCipherSuites) > 0 {
		parsed.tlsCipherSuites = make([]uint16, 0, len(config.tlsCurvePreferences))
		for _, cipher := range config.tlsCipherSuites {
			switch cipher {
			case "TLS_FALLBACK_SCSV":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_FALLBACK_SCSV)
			case "TLS_RSA_WITH_RC4_128_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_RC4_128_SHA)
			case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
			case "TLS_RSA_WITH_AES_128_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
			case "TLS_RSA_WITH_AES_256_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_AES_256_CBC_SHA)
			case "TLS_RSA_WITH_AES_128_CBC_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA256)
			case "TLS_RSA_WITH_AES_128_GCM_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
			case "TLS_RSA_WITH_AES_256_GCM_SHA384":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_RSA_WITH_AES_256_GCM_SHA384)
			case "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
			case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
			case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)
			case "TLS_ECDHE_RSA_WITH_RC4_128_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)
			case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)
			case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
			case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
			case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
			case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)
			case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
			case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
			case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
			case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
			case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305)
			case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305)
			case "TLS_CHACHA20_POLY1305_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_CHACHA20_POLY1305_SHA256)
			case "TLS_AES_128_GCM_SHA256":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_AES_128_GCM_SHA256)
			case "TLS_AES_256_GCM_SHA384":
				parsed.tlsCipherSuites = append(parsed.tlsCipherSuites, tls.TLS_AES_256_GCM_SHA384)
			default:
				return nil, errors.New("invalid TLS cipher suite configured. Accepted values are listed at https://golang.org/pkg/crypto/tls/#pkg-constants")
			}
		}
		if config.tlsUseModernSettings && len(config.tlsCurvePreferences) == 0 {
			// Use modern tls mode https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility
			// See security linter code: https://github.com/securego/gosec/blob/master/rules/tls_config.go#L11
			// These ciphersuites support Forward Secrecy: https://en.wikipedia.org/wiki/Forward_secrecy
			parsed.tlsCipherSuites = []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
			}
		}
		// when some cipher preferences are explicitly provided, enforce the presence of TLS_FALLBACK_SCSV
		// at the top of cipher suites preferences.
		// When no suites are specified, stick to golang's defaults.
		if len(parsed.tlsCipherSuites) > 0 {
			enforcedSCSV := make([]uint16, 1, len(parsed.tlsCipherSuites)+1)
			enforcedSCSV[0] = tls.TLS_FALLBACK_SCSV
			for _, cph := range parsed.tlsCipherSuites {
				if cph == tls.TLS_FALLBACK_SCSV {
					continue
				}
				enforcedSCSV = append(enforcedSCSV, cph)
			}
			parsed.tlsCipherSuites = enforcedSCSV
		}
	}
	return parsed, nil
}

func (r *Config) isListenValid() error {
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	if r.ListenAdmin == r.Listen {
		r.ListenAdmin = ""
	}
	if r.ListenAdminScheme == "" {
		r.ListenAdminScheme = secureScheme
	}
	if r.ListenAdminScheme != secureScheme && r.ListenAdminScheme != unsecureScheme {
		return errors.New("scheme for admin listener must be one of [http, https]")
	}
	if r.MaxIdleConns <= 0 {
		return errors.New("max-idle-connections must be a number > 0")
	}
	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return errors.New("maxi-idle-connections-per-host must be a number > 0 and <= max-idle-connections")
	}
	return nil
}

func (r *Config) isTLSValid() error {
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return errors.New("you have not provided a private key")
	}
	if r.TLSAdminCertificate != "" && r.TLSAdminPrivateKey == "" {
		return errors.New("you have not provided a private key for admin endpoint")
	}
	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return errors.New("you have not provided a certificate file")
	}
	if r.TLSAdminPrivateKey != "" && r.TLSAdminCertificate == "" {
		return errors.New("you have not provided a certificate file for admin endpoint")
	}
	if r.TLSCertificate != "" && !fileExists(r.TLSCertificate) {
		return fmt.Errorf("the tls certificate %s does not exist", r.TLSCertificate)
	}
	if r.TLSAdminCertificate != "" && !fileExists(r.TLSAdminCertificate) {
		return fmt.Errorf("the tls certificate %s does not exist for admin endpoint", r.TLSAdminCertificate)
	}
	if r.TLSPrivateKey != "" && !fileExists(r.TLSPrivateKey) {
		return fmt.Errorf("the tls private key %s does not exist", r.TLSPrivateKey)
	}
	if r.TLSAdminPrivateKey != "" && !fileExists(r.TLSAdminPrivateKey) {
		return fmt.Errorf("the tls private key %s does not exist for admin endpoint", r.TLSAdminPrivateKey)
	}
	if r.TLSCaCertificate != "" && !fileExists(r.TLSCaCertificate) {
		return fmt.Errorf("the tls ca certificate file %s does not exist", r.TLSCaCertificate)
	}
	if r.TLSAdminCaCertificate != "" && !fileExists(r.TLSAdminCaCertificate) {
		return fmt.Errorf("the tls ca certificate file %s does not exist for admin endpoint", r.TLSAdminCaCertificate)
	}
	if r.TLSClientCertificate != "" && len(r.TLSClientCertificates) > 0 {
		return fmt.Errorf("specify only one of single TLSAdminClientCertificate or array TLSAdminClientCertificates")
	}
	if r.TLSClientCertificate != "" && !fileExists(r.TLSClientCertificate) {
		return fmt.Errorf("the tls client certificate %s does not exist", r.TLSClientCertificate)
	}
	for _, clientCertFile := range r.TLSClientCertificates {
		if !fileExists(clientCertFile) {
			return fmt.Errorf("the tls client certificate %s does not exist", clientCertFile)
		}
	}
	if r.TLSAdminClientCertificate != "" && len(r.TLSAdminClientCertificates) > 0 {
		return fmt.Errorf("specify only one of single TLSAdminClientCertificate or array TLSAdminClientCertificates")
	}
	if r.TLSAdminClientCertificate != "" && !fileExists(r.TLSAdminClientCertificate) {
		return fmt.Errorf("the tls client certificate %s does not exist for admin endpoint", r.TLSAdminClientCertificate)
	}
	for _, clientCertFile := range r.TLSAdminClientCertificates {
		if !fileExists(clientCertFile) {
			return fmt.Errorf("the tls client certificate %s does not exist for admin endpoint", clientCertFile)
		}
	}
	return nil
}

func (r *Config) isReverseProxyValid() error {
	switch r.Upstream {
	case "":
		if r.EnableDefaultDeny && !r.EnableDefaultNotFound {
			return errors.New("you expect some default fallback routing, but have not specified an upstream endpoint to proxy to")
		}
		for _, resource := range r.Resources {
			if resource.Upstream == "" {
				return fmt.Errorf("you did not set any default upstream and you have not specified an upstream endpoint to proxy to on resource: %s", resource.URL)
			}
		}
	default:
		if _, err := url.Parse(r.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %s", err)
		}
	}

	if !r.SkipUpstreamTLSVerify && r.UpstreamCA == "" {
		return fmt.Errorf("you cannot require to check upstream tls and omit to specify the root ca to verify it: %s", r.UpstreamCA)
	}

	// step: if token verification is enabled (skip is off), we need the below checks
	if !r.SkipTokenVerification {
		if err := r.isTokenConfigValid(); err != nil {
			return err
		}
	}
	// check: ensure each of the resource are valid
	for _, resource := range r.Resources {
		if err := resource.valid(); err != nil {
			return err
		}
		if resource.URL == allRoutes && r.EnableDefaultDeny && resource.WhiteListed {
			return errors.New("you've asked for a default denial (EnableDefaultDeny is true by default) but whitelisted everything")
		}
	}
	// step: validate the claims are validate regex's
	for k, claim := range r.MatchClaims {
		if _, err := regexp.Compile(claim); err != nil {
			return fmt.Errorf("the claim matcher: %s for claim: %s is not a valid regex", claim, k)
		}
	}

	// step: validity checks for CSRF options
	if r.EnableCSRF {
		if r.EncryptionKey == "" {
			return fmt.Errorf("flag EnableCSRF requires EncryptionKey to be set")
		}
		var found bool
		for _, resource := range r.Resources {
			if resource.EnableCSRF {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("flag EnableCSRF is set but no protected resource sets EnableCSRF")
		}
	}
	return nil
}

func (r *Config) isDiscoveryValid() error {
	if r.DiscoveryURL == "" {
		return errors.New("you have not specified the discovery url")
	}
	if u, err := url.Parse(r.DiscoveryURL); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("discovery url is not a valid URL: %s", r.DiscoveryURL)
	}
	return nil
}

func (r *Config) isTokenConfigValid() error {
	if r.ClientID == "" {
		return errors.New("you have not specified the client id")
	}
	if err := r.isDiscoveryValid(); err != nil {
		return err
	}
	if strings.HasSuffix(r.RedirectionURL, "/") {
		r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
	}
	if r.RedirectionURL != "" {
		if _, err := url.Parse(r.RedirectionURL); err != nil {
			return fmt.Errorf("redirection url is not a valid URL: %s", r.RedirectionURL)
		}
	}
	if !r.EnableSecurityFilter {
		if r.EnableHTTPSRedirect {
			return errors.New("the security filter must be switched on for this feature: http-redirect")
		}
		if r.EnableBrowserXSSFilter {
			return errors.New("the security filter must be switched on for this feature: brower-xss-filter")
		}
		if r.EnableFrameDeny {
			return errors.New("the security filter must be switched on for this feature: frame-deny-filter")
		}
		if r.ContentSecurityPolicy != "" {
			return errors.New("the security filter must be switched on for this feature: content-security-policy")
		}
		if len(r.Hostnames) > 0 {
			return errors.New("the security filter must be switched on for this feature: hostnames")
		}
	}

	if (r.EnableEncryptedToken || r.ForceEncryptedCookie) && r.EncryptionKey == "" {
		return errors.New("you have not specified an encryption key for encoding the access token")
	}
	if r.EnableRefreshTokens && r.EncryptionKey == "" {
		return errors.New("you have not specified an encryption key for encoding the session state")
	}
	if r.EnableRefreshTokens && (len(r.EncryptionKey) != 16 && len(r.EncryptionKey) != 32) {
		return fmt.Errorf("the encryption key (%d) must be either 16 or 32 characters for AES-128/AES-256 selection", len(r.EncryptionKey))
	}
	if !r.NoRedirects && r.SecureCookie && r.RedirectionURL != "" && !strings.HasPrefix(r.RedirectionURL, "https") {
		return errors.New("the cookie is set to secure but your redirection url is non-tls")
	}

	if err := r.isStoreValid(); err != nil {
		return err
	}
	return nil
}

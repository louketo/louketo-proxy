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
	hostnames = append(hostnames, []string{"localhost", "127.0.0.1"}...)

	return &Config{
		AccessTokenDuration:           time.Duration(720) * time.Hour,
		CookieAccessName:              accessCookie,
		CookieRefreshName:             refreshCookie,
		EnableAuthorizationCookies:    true,
		EnableAuthorizationHeader:     true,
		EnableDefaultDeny:             true,
		EnableSessionCookies:          true,
		EnableTokenHeader:             true,
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
		SecureCookie:                  true,
		ServerIdleTimeout:             120 * time.Second,
		ServerReadTimeout:             10 * time.Second,
		ServerWriteTimeout:            10 * time.Second,
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
		EnableCSRF:                    false,
		CSRFCookieName:                "kc-csrf",
		CSRFHeader:                    "X-Csrf-Token",
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
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	if r.MaxIdleConns <= 0 {
		return errors.New("max-idle-connections must be a number > 0")
	}
	if r.MaxIdleConnsPerHost < 0 || r.MaxIdleConnsPerHost > r.MaxIdleConns {
		return errors.New("maxi-idle-connections-per-host must be a number > 0 and <= max-idle-connections")
	}
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return errors.New("you have not provided a private key")
	}
	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return errors.New("you have not provided a certificate file")
	}
	if r.TLSCertificate != "" && !fileExists(r.TLSCertificate) {
		return fmt.Errorf("the tls certificate %s does not exist", r.TLSCertificate)
	}
	if r.TLSPrivateKey != "" && !fileExists(r.TLSPrivateKey) {
		return fmt.Errorf("the tls private key %s does not exist", r.TLSPrivateKey)
	}
	if r.TLSCaCertificate != "" && !fileExists(r.TLSCaCertificate) {
		return fmt.Errorf("the tls ca certificate file %s does not exist", r.TLSCaCertificate)
	}
	if r.TLSClientCertificate != "" && !fileExists(r.TLSClientCertificate) {
		return fmt.Errorf("the tls client certificate %s does not exist", r.TLSClientCertificate)
	}
	if r.UseLetsEncrypt && r.LetsEncryptCacheDir == "" {
		return fmt.Errorf("the letsencrypt cache dir has not been set")
	}

	if r.EnableForwarding {
		if r.ClientID == "" {
			return errors.New("you have not specified the client id")
		}
		if r.DiscoveryURL == "" {
			return errors.New("you have not specified the discovery url")
		}
		if r.ForwardingUsername == "" {
			return errors.New("no forwarding username")
		}
		if r.ForwardingPassword == "" {
			return errors.New("no forwarding password")
		}
		if r.TLSCertificate != "" {
			return errors.New("you don't need to specify a tls-certificate, use tls-ca-certificate instead")
		}
		if r.TLSPrivateKey != "" {
			return errors.New("you don't need to specify the tls-private-key, use tls-ca-key instead")
		}
	} else {
		if r.Upstream == "" {
			return errors.New("you have not specified an upstream endpoint to proxy to")
		}
		if _, err := url.Parse(r.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %s", err)
		}
		if r.SkipUpstreamTLSVerify && r.UpstreamCA != "" {
			return fmt.Errorf("you cannot skip upstream tls and load a root ca: %s to verify it", r.UpstreamCA)
		}

		// step: if the skip verification is off, we need the below
		if !r.SkipTokenVerification {
			if r.ClientID == "" {
				return errors.New("you have not specified the client id")
			}
			if r.DiscoveryURL == "" {
				return errors.New("you have not specified the discovery url")
			}
			if strings.HasSuffix(r.RedirectionURL, "/") {
				r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
			}
			if !r.EnableSecurityFilter {
				if r.EnableHTTPSRedirect {
					return errors.New("the security filter must be switch on for this feature: http-redirect")
				}
				if r.EnableBrowserXSSFilter {
					return errors.New("the security filter must be switch on for this feature: brower-xss-filter")
				}
				if r.EnableFrameDeny {
					return errors.New("the security filter must be switch on for this feature: frame-deny-filter")
				}
				if r.ContentSecurityPolicy != "" {
					return errors.New("the security filter must be switch on for this feature: content-security-policy")
				}
				if len(r.Hostnames) > 0 {
					return errors.New("the security filter must be switch on for this feature: hostnames")
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
			if r.StoreURL != "" {
				if _, err := url.Parse(r.StoreURL); err != nil {
					return fmt.Errorf("the store url is invalid, error: %s", err)
				}
			}
		}
		// check: ensure each of the resource are valid
		for _, resource := range r.Resources {
			if err := resource.valid(); err != nil {
				return err
			}
		}
		// step: validate the claims are validate regex's
		for k, claim := range r.MatchClaims {
			if _, err := regexp.Compile(claim); err != nil {
				return fmt.Errorf("the claim matcher: %s for claim: %s is not a valid regex", claim, k)
			}
		}
	}

	// validity checks with CSRF options
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
		if r.CorsDisableUpstream {
			return fmt.Errorf("flag EnableCSRF requires headers to be added to upstream response. This won't work if CorsDisableUpstream is set")
		}
	}
	return nil
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
		case "SSL3.0":
			parsed.tlsMinVersion = tls.VersionSSL30
		case "TLS1.0":
			parsed.tlsMinVersion = tls.VersionTLS10
		case "TLS1.1":
			parsed.tlsMinVersion = tls.VersionTLS11
		case "TLS1.2":
			parsed.tlsMinVersion = tls.VersionTLS12
		default:
			return nil, errors.New("invalid TLS version configured. Accepted values are: SSL3.0, TLS1.0, TLS1.1, TLS1.2")
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
			}
		}
	}
	return parsed, nil
}

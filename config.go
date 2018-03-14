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
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// newDefaultConfig returns a initialized config
func newDefaultConfig() *Config {
	return &Config{
		AccessTokenDuration:         time.Duration(720) * time.Hour,
		CookieAccessName:            "kc-access",
		CookieRefreshName:           "kc-state",
		EnableAuthorizationCookies:  true,
		EnableAuthorizationHeader:   true,
		EnableTokenHeader:           true,
		Headers:                     make(map[string]string),
		LetsEncryptCacheDir:         "./cache/",
		MatchClaims:                 make(map[string]string),
		OAuthURI:                    "/oauth",
		OpenIDProviderTimeout:       30 * time.Second,
		SecureCookie:                true,
		ServerIdleTimeout:           120 * time.Second,
		ServerReadTimeout:           5 * time.Second,
		ServerWriteTimeout:          10 * time.Second,
		SkipOpenIDProviderTLSVerify: false,
		SkipUpstreamTLSVerify:       true,
		Tags: make(map[string]string, 0),
		UpstreamExpectContinueTimeout: 10 * time.Second,
		UpstreamKeepaliveTimeout:      10 * time.Second,
		UpstreamKeepalives:            true,
		UpstreamResponseHeaderTimeout: 1 * time.Second,
		UpstreamTLSHandshakeTimeout:   10 * time.Second,
		UpstreamTimeout:               10 * time.Second,
		UseLetsEncrypt:                false,
	}
}

// WithOAuthURI returns the oauth uri
func (r *Config) WithOAuthURI(uri string) string {
	return fmt.Sprintf("%s/%s", r.OAuthURI, uri)
}

// isValid validates if the config is valid
func (r *Config) isValid() error {
	if r.Listen == "" {
		return errors.New("you have not specified the listening interface")
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
			if r.EnableEncryptedToken && r.EncryptionKey == "" {
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

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

// NewDefaultConfig returns a initialized config
func NewDefaultConfig() *Config {
	return &Config{
		AccessTokenDuration:         time.Duration(720) * time.Hour,
		CookieAccessName:            "kc-access",
		CookieRefreshName:           "kc-state",
		EnableAuthorizationHeader:   true,
		EnableAuthorizationCookies:  true,
		EnableTokenHeader:           true,
		Headers:                     make(map[string]string),
		LetsEncryptCacheDir:         "./cache/",
		MatchClaims:                 make(map[string]string),
		SecureCookie:                true,
		ServerIdleTimeout:           120 * time.Second,
		ServerReadTimeout:           5 * time.Second,
		ServerWriteTimeout:          10 * time.Second,
		SkipOpenIDProviderTLSVerify: false,
		SkipUpstreamTLSVerify:       true,
		Tags: make(map[string]string, 0),
		UpstreamExpectContinueTimeout: 10 * time.Second,
		UpstreamKeepaliveTimeout:      10 * time.Second,
		UpstreamResponseHeaderTimeout: 1 * time.Second,
		UpstreamTLSHandshakeTimeout:   10 * time.Second,
		UpstreamTimeout:               10 * time.Second,
		UseLetsEncrypt:                false,
	}
}

// IsValid validates if the config is valid
func (c *Config) IsValid() error {
	if c.Listen == "" {
		return errors.New("you have not specified the listening interface")
	}
	if c.TLSCertificate != "" && c.TLSPrivateKey == "" {
		return errors.New("you have not provided a private key")
	}
	if c.TLSPrivateKey != "" && c.TLSCertificate == "" {
		return errors.New("you have not provided a certificate file")
	}
        if c.UseLetsEncrypt && c.LetsEncryptCacheDir == "" {
		return fmt.Errorf("the letsencrypt cache dir has not been set")
	}

	if r.EnableForwarding {
		if c.ClientID == "" {
			return errors.New("you have not specified the client id")
		}
		if c.DiscoveryURL == "" {
			return errors.New("you have not specified the discovery url")
		}
		if c.ForwardingUsername == "" {
			return errors.New("no forwarding username")
		}
		if c.ForwardingPassword == "" {
			return errors.New("no forwarding password")
		}
		if c.TLSCertificate != "" {
			return errors.New("you don't need to specify a tls-certificate, use tls-ca-certificate instead")
		}
		if c.TLSPrivateKey != "" {
			return errors.New("you don't need to specify the tls-private-key, use tls-ca-key instead")
		}
	} else {
		if c.Upstream == "" {
			return errors.New("you have not specified an upstream endpoint to proxy to")
		}
		if _, err := url.Parse(c.Upstream); err != nil {
			return fmt.Errorf("the upstream endpoint is invalid, %s", err)
		}
		if r.SkipUpstreamTLSVerify && r.UpstreamCA != "" {
			return fmt.Errorf("you cannot skip upstream tls and load a root ca: %s to verify it", r.UpstreamCA)
		}

		// step: if the skip verification is off, we need the below
		if !c.SkipTokenVerification {
			if c.ClientID == "" {
				return errors.New("you have not specified the client id")
			}
			if c.DiscoveryURL == "" {
				return errors.New("you have not specified the discovery url")
			}
			if strings.HasSuffix(c.RedirectionURL, "/") {
				c.RedirectionURL = strings.TrimSuffix(c.RedirectionURL, "/")
			}
			if !c.EnableSecurityFilter {
				if c.EnableHTTPSRedirect {
					return errors.New("the security filter must be switch on for this feature: http-redirect")
				}
				if c.EnableBrowserXSSFilter {
					return errors.New("the security filter must be switch on for this feature: brower-xss-filter")
				}
				if c.EnableFrameDeny {
					return errors.New("the security filter must be switch on for this feature: frame-deny-filter")
				}
				if c.ContentSecurityPolicy != "" {
					return errors.New("the security filter must be switch on for this feature: content-security-policy")
				}
				if len(c.Hostnames) > 0 {
					return errors.New("the security filter must be switch on for this feature: hostnames")
				}
			}
			if c.EnableEncryptedToken && c.EncryptionKey == "" {
				return errors.New("you have not specified an encryption key for encoding the access token")
			}
			if c.EnableRefreshTokens && c.EncryptionKey == "" {
				return errors.New("you have not specified an encryption key for encoding the session state")
			}
			if c.EnableRefreshTokens && (len(c.EncryptionKey) != 16 && len(c.EncryptionKey) != 32) {
				return fmt.Errorf("the encryption key (%d) must be either 16 or 32 characters for AES-128/AES-256 selection", len(c.EncryptionKey))
			}
			if !c.NoRedirects && c.SecureCookie && c.RedirectionURL != "" && !strings.HasPrefix(c.RedirectionURL, "https") {
				return errors.New("the cookie is set to secure but your redirection url is non-tls")
			}
			if c.StoreURL != "" {
				if _, err := url.Parse(c.StoreURL); err != nil {
					return fmt.Errorf("the store url is invalid, error: %s", err)
				}
			}
		}
		// check: ensure each of the resource are valid
		for _, resource := range c.Resources {
			if err := resource.IsValid(); err != nil {
				return err
			}
		}
		// step: validate the claims are validate regex's
		for k, claim := range c.MatchClaims {
			if _, err := regexp.Compile(claim); err != nil {
				return fmt.Errorf("the claim matcher: %s for claim: %s is not a valid regex", claim, k)
			}
		}
	}

	return nil
}

// HasCustomSignInPage check if a custom page is require
func (c *Config) HasCustomSignInPage() bool {
	return c.SignInPage != ""
}

// HasCustomForbiddenPage checks if we have a custom forbidden page
func (c *Config) HasCustomForbiddenPage() bool {
	return c.ForbiddenPage != ""
}

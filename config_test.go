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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultConfig(t *testing.T) {
	if config := newDefaultConfig(); config == nil {
		t.Error("we should have received a config")
	}
}

func TestIsConfigValid(t *testing.T) {
	tests := []struct {
		Name          string
		Config        *Config
		Ok            bool
		Error         string
		ExtraAsserter func(testing.TB, Config)
	}{
		{
			Name:   "empty config",
			Config: &Config{},
			Error:  "you have not specified the listening interface",
		},
		{
			Name: "missing client ID",
			Config: &Config{
				Listen:                ":8080",
				MaxIdleConns:          10,
				SkipUpstreamTLSVerify: true,
			},
			Error: "you have not specified the client id",
		},
		{
			Name: "wrong discovery URL",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "wrong",
				MaxIdleConns:          10,
				ClientID:              "client",
				SkipUpstreamTLSVerify: true,
			},
			Error: "discovery url is not a valid URL",
		},
		{
			Name: "wrong idle ",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				MaxIdleConns:          -10,
				SkipUpstreamTLSVerify: true,
			},
			Error: "max-idle-connections must be a number > 0",
		},
		{
			Name: "wrong missing CA",
			Config: &Config{
				Listen:       ":8080",
				DiscoveryURL: "http://127.0.0.1:8080",
				ClientID:     "client",
				ClientSecret: "client",
				MaxIdleConns: 10,
			},
			Error: "you cannot require to check upstream tls and omit to specify the root ca to verify it",
		},
		{
			Name: "wrong invalid upstream",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				MaxIdleConns:          10,
				SkipUpstreamTLSVerify: true,
				Upstream:              "httpxxyz@:xxx/nowhere",
			},
			Error: "upstream endpoint is invalid",
		},
		{
			Name: "missing discovery url",
			Config: &Config{
				Listen:         ":8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
				UpstreamCA:     "someCA",
				MaxIdleConns:   10,
			},
			Error: "you have not specified the discovery url",
		},
		{
			Name: "max-idle-connections > 0",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				SkipUpstreamTLSVerify: false,
				Upstream:              "http://120.0.0.1",
				UpstreamCA:            "someCA",
				MaxIdleConns:          0,
				MaxIdleConnsPerHost:   0,
			},
			Error: "max-idle-connections must be a number > 0",
		},
		{
			Name: "max-idle vs max-ide per host",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				Upstream:              "http://120.0.0.1",
				SkipUpstreamTLSVerify: false,
				UpstreamCA:            "someCA",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   200,
			},
			Error: "maxi-idle-connections-per-host must be a number > 0 and <= max-idle-connections",
		},
		{
			Name: "invalid claim matcher",
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
				UpstreamCA:     "someCA",
				MatchClaims: map[string]string{
					"test": "&&&[",
				},
				SkipUpstreamTLSVerify: true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Error: "is not a valid regex",
		},
		{
			Name: "invalid CSFR flag",
			Config: &Config{
				DiscoveryURL:          "http://127.0.0.1:8080",
				Listen:                ":8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				SkipUpstreamTLSVerify: true,
				Upstream:              "http://120.0.0.1",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				EnableCSRF:            true,
			},
			Error: "flag EnableCSRF requires EncryptionKey to be set",
		},
		{
			Name: "invalid CSRF flag (2)",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				SkipUpstreamTLSVerify: true,
				Upstream:              "http://120.0.0.1",
				EnableCSRF:            true,
				EncryptionKey:         "xx",
				Resources: []*Resource{
					&Resource{
						URL: "http://localhost/there",
					},
				},
			},
			Error: "EnableCSRF is set but no protected resource sets EnableCSRF",
		},
		{
			Name: "invalid upstream override",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				SkipUpstreamTLSVerify: true,
				EnableCSRF:            true,
				EncryptionKey:         "xx",
				Resources: []*Resource{
					&Resource{
						URL: "http://localhost/there",
					},
				},
			},
			Error: "you did not set any default upstream and you have not specified an upstream endpoint to proxy to on resource",
		},
		{
			Name: "invalid TLS",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				SkipUpstreamTLSVerify: false,
				Upstream:              "this is a valid URL!!",
				UpstreamCA:            "ca.crt",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				TLSPrivateKey:         "key.crt",
			},
			Error: "you have not provided a certificate file",
		},
		{
			Name: "invalid upstream",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "https://120.0.0.1",
				SkipUpstreamTLSVerify: true,
				Upstream:              "ht@:this should fail",
				SecureCookie:          true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Error: "the upstream endpoint is invalid",
		},
		{
			Name: "invalid uri",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "https://120.0.0.1",
				SkipUpstreamTLSVerify: true,
				Upstream:              "https://upstream:",
				SecureCookie:          true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				Resources: []*Resource{
					&Resource{
						URL:  "/nowhere",
						URLs: []string{"/somewhere"},
					},
				},
			},
			Error: "can't specify both uri and uris",
		},
		{
			Name: "duplicate resources",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "https://120.0.0.1",
				SkipUpstreamTLSVerify: true,
				Upstream:              "this should not fail",
				SecureCookie:          true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				Resources: []*Resource{
					&Resource{
						URLs: []string{"/somewhere", "/everywhere"},
					},
					&Resource{
						URL: "/somewhere",
					},
				},
			},
			Error: "a duplicate entry in resource URIs has been found",
		},
		{
			Name: "happy path",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "http://120.0.0.1",
				SkipUpstreamTLSVerify: false,
				Upstream:              "http://120.0.0.1",
				UpstreamCA:            "someCA",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Ok: true,
		},
		{
			Name: "happy path",
			Config: &Config{
				Listen:                ":8080",
				SkipTokenVerification: true,
				Upstream:              "http://120.0.0.1",
				UpstreamCA:            "someCA",
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Ok: true,
		},
		{
			Name: "happy path",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "https://120.0.0.1",
				SkipUpstreamTLSVerify: true,
				Upstream:              "this should not fail",
				SecureCookie:          true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
			},
			Ok: true,
		},
		{
			Name: "happy path",
			Config: &Config{
				Listen:                ":8080",
				DiscoveryURL:          "http://127.0.0.1:8080",
				ClientID:              "client",
				ClientSecret:          "client",
				RedirectionURL:        "https://120.0.0.1",
				SkipUpstreamTLSVerify: true,
				Upstream:              "this should not fail",
				SecureCookie:          true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   50,
				Resources: []*Resource{
					&Resource{
						URLs: []string{"/somewhere", "/everywhere"},
					},
				},
			},
			Ok: true,
			ExtraAsserter: func(t testing.TB, config Config) {
				assert.Len(t, config.Resources, 2)
			},
		},
	}

	for i, c := range tests {
		err := c.Config.isValid()
		if c.Ok {
			assert.NoErrorf(t, err, "test case %d (%q), the config should not have errored, error: %v", i, c.Name, err)
		} else {
			assert.Errorf(t, err, "test case %d (%q), the config should have errored", i, c.Name)
			t.Logf("test case %d (%q), got error: %v", i, c.Name, err)
			if c.Error != "" && err != nil {
				assert.Contains(t, err.Error(), c.Error)
			}
		}
	}
}

func TestParseTLS(t *testing.T) {
	tlsConfigFixture := tlsAdvancedConfig{
		tlsPreferServerCipherSuites: true,
		tlsMinVersion:               "TLS1.1",
		tlsCipherSuites:             []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		tlsCurvePreferences:         []string{"P384"},
	}
	res, err := parseTLS(&tlsConfigFixture)
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.Equal(t, &tlsSettings{
			tlsPreferServerCipherSuites: true,
			tlsMinVersion:               tls.VersionTLS11,
			tlsCipherSuites:             []uint16{tls.TLS_FALLBACK_SCSV, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			tlsCurvePreferences:         []tls.CurveID{tls.CurveP384},
		}, res)
	}

	tlsConfigFixture = tlsAdvancedConfig{
		tlsUseModernSettings: true,
	}
	res, err = parseTLS(&tlsConfigFixture)
	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.Equal(t, &tlsSettings{
			tlsPreferServerCipherSuites: true,
			tlsMinVersion:               tls.VersionTLS12,
			tlsCipherSuites: []uint16{
				tls.TLS_FALLBACK_SCSV,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
			},
			tlsCurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		}, res)
	}
}

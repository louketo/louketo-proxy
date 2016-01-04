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
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
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
	// DiscoveryURL is the url for the keycloak server
	DiscoveryURL string `json:"discovery_url" yaml:"discovery_url"`
	// LogRequest enables logging
	LogRequests bool `json:"log_requests" yaml:"log_requests"`
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
	// MaxSessionDuration the max session for refreshing
	MaxSessionDuration time.Duration `json:"max_session" yaml:"max_session"`
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
	// Scopes is a list of scope we should request
	Scopes []string `json:"scopes" yaml:"scopes"`
	// Resources is a list of protected resources
	Resources []*Resource `json:"resources" yaml:"resources"`
	// SignInPageis the relative url for the sign in page
	SignInPage string `json:"sign_in_page" yaml:"sign_in_page"`
	// AccessForbiddenPage is a access forbidden page
	AccessForbiddenPage string `json:"access_forbidden_page" yaml:"access_forbidden_page"`
}

var (
	cfgFilename string
)

func init() {
	flag.StringVar(&cfgFilename, "config", "", "the path to the configuration file for the keycloak proxy service, in yaml or json format")
}

// parseConfig parse a configuration file or yaml or json and extracts the config
func parseConfig(filename string) (*Config, error) {
	// step: ensure we have a configuration file
	if filename == "" {
		usage("you have not specified the configuration file")
	}

	// step: attempt to parse the configuration file
	config, err := parseConfigFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read the configuratiom file: %s, %s", filename, err)
	}

	// step: validate the configuration
	if config.Upstream == "" {
		return nil, fmt.Errorf("you have not specified an upstream endpoint to proxy to")
	}

	if _, err := url.Parse(config.Upstream); err != nil {
		return nil, fmt.Errorf("the upstream endpoint is invalid, %s", err)
	}
	if config.DiscoveryURL == "" {
		return nil, fmt.Errorf("you have not specified the discovery url")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("you have not specified the client id")
	}
	if config.Secret == "" {
		return nil, fmt.Errorf("you have not specified the client secret")
	}
	if config.RedirectionURL == "" {
		return nil, fmt.Errorf("you have not specified the redirection url")
	}
	if strings.HasSuffix(config.RedirectionURL, "/") {
		config.RedirectionURL = strings.TrimSuffix(config.RedirectionURL, "/")
	}
	if config.Listen == "" {
		config.Listen = ":8081"
	}
	if config.EncryptionKey == "" && config.RefreshSession {
		return nil, fmt.Errorf("you have not specified a encryption key for encoding the session state")
	}
	if config.MaxSessionDuration == 0 && config.RefreshSession {
		config.MaxSessionDuration = time.Duration(6) * time.Hour
	}

	for i, resource := range config.Resources {
		if len(resource.Methods) <= 0 {
			resource.Methods = append(resource.Methods, "ANY")
		}
		if resource.URL == "" {
			return nil, fmt.Errorf("resource %d does not have url", i)
		}
		for _, m := range resource.Methods {
			if !isValidMethod(m) {
				return nil, fmt.Errorf("the resource method: %s for url: %s is invalid", m, resource.URL)
			}
		}
	}

	return config, nil
}

// usage displays the usage menu and exits
func usage(message string) {
	fmt.Fprintf(os.Stderr, "\n[error] %s\n", message)
	os.Exit(1)
}

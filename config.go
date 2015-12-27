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
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/codegangsta/cli"
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
	// Debug switches on debug logging
	Debug bool `json:"debug" yaml:"debug"`
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
	// RefreshSession enabled refresh access
	RefreshSession bool `json:"refresh_session" yaml:"refresh_session"`
	// EncryptionKey is the encryption key used to encrypt the refresh token
	EncryptionKey string `json:"encryption_key" yaml:"encryption_key"`
	// MaxSessionDuration the max session for refreshing
	MaxSession time.Duration `json:"max_session" yaml:"max_session"`
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
	// SignInPage is the relative url for the sign in page
	SignInPage string `json:"sign_in_page" yaml:"sign_in_page"`
	// AccessForbiddenPage is a access forbidden page
	AccessForbiddenPage string `json:"access_forbidden_page" yaml:"access_forbidden_page"`
}

// parseConfig reads in the proxy configuration
func parseConfig(cx *cli.Context) (*Config, error) {
	var err error
	config := new(Config)

	// step: process any configuration file
	configFile := cx.String("config")
	if configFile != "" {
		err = readConfigurationFile(configFile, config)
		if err != nil {
			return nil, err
		}
	}
	if cx.IsSet("listen") {
		config.Listen = cx.String("listen")
	}
	if cx.IsSet("secret") {
		config.Secret = cx.String("secret")
	}
	if cx.IsSet("client-id") {
		config.ClientID = cx.String("client-id")
	}
	if cx.IsSet("discovery-url") {
		config.DiscoveryURL = cx.String("discovery-url")
	}
	if cx.IsSet("upstream-url") {
		config.Upstream = cx.String("upstream-url")
	}
	if cx.IsSet("encryption-key") {
		config.EncryptionKey = cx.String("encryption-key")
	}
	if cx.IsSet("redirection-url") {
		config.RedirectionURL = cx.String("redirection-url")
	}
	if cx.IsSet("tls-cert") {
		config.TLSCertificate = cx.String("tls-cert")
	}
	if cx.IsSet("tls-private-key") {
		config.TLSPrivateKey = cx.String("tls-private-key")
	}
	if cx.IsSet("signin-page") {
		config.SignInPage = cx.String("signin-page")
	}
	if cx.IsSet("forbidden-page") {
		config.AccessForbiddenPage = cx.String("forbidden-page")
	}
	if cx.IsSet("max-session") {
		config.MaxSession = cx.Duration("max-session")
	}
	if cx.IsSet("proxy-protocol") {
		config.ProxyProtocol = cx.Bool("proxy-protocol")
	}
	if cx.IsSet("refresh-sessions") {
		config.RefreshSession = cx.Bool("refresh-sessions")
	}
	if cx.IsSet("json-logging") {
		config.LogJSONFormat = cx.Bool("json-logging")
	}
	if cx.IsSet("log-requests") {
		config.LogRequests = cx.Bool("log-requests")
	}
	if cx.IsSet("scope") {
		config.Scopes = cx.StringSlice("scope")
	}
	// step: decode the resources
	if cx.IsSet("resource") {
		for _, x := range cx.StringSlice("resource") {
			resource, err := decodeResource(x)
			if err != nil {
				return nil, fmt.Errorf("invalid resource %s, %s", x, err)
			}

			config.Resources = append(config.Resources, resource)
		}
	}

	return config, nil
}

// validateConfig validates we have all the required options / config
func validateConfig(config *Config) error {
	// step: validate the configuration
	if config.Upstream == "" {
		return fmt.Errorf("you have not specified an upstream endpoint to proxy to")
	}
	if _, err := url.Parse(config.Upstream); err != nil {
		return fmt.Errorf("the upstream endpoint is invalid, %s", err)
	}
	if config.DiscoveryURL == "" {
		return fmt.Errorf("you have not specified the discovery url")
	}
	if config.ClientID == "" {
		return fmt.Errorf("you have not specified the client id")
	}
	if config.Secret == "" {
		return fmt.Errorf("you have not specified the client secret")
	}
	if config.RedirectionURL == "" {
		return fmt.Errorf("you have not specified the redirection url")
	}
	if strings.HasSuffix(config.RedirectionURL, "/") {
		config.RedirectionURL = strings.TrimSuffix(config.RedirectionURL, "/")
	}
	if config.Listen == "" {
		return fmt.Errorf("you have not specified the listening interface")
	}
	if config.EncryptionKey == "" && config.RefreshSession {
		return fmt.Errorf("you have not specified a encryption key for encoding the session state")
	}
	if config.EncryptionKey != "" && len(config.EncryptionKey) < 32 {
		return fmt.Errorf("the encryption key is too short, must be longer than 32 characters")
	}
	if config.MaxSession == 0 && config.RefreshSession {
		config.MaxSession = time.Duration(6) * time.Hour
	}

	for i, resource := range config.Resources {
		if resource.Methods == nil {
			resource.Methods = make([]string, 0)
		}
		if resource.RolesAllowed == nil {
			resource.RolesAllowed = make([]string, 0)
		}
		if len(resource.Methods) <= 0 {
			resource.Methods = append(resource.Methods, "ANY")
		}
		if resource.URL == "" {
			return fmt.Errorf("resource %d does not have url", i)
		}
		for _, m := range resource.Methods {
			if !isValidMethod(m) {
				return fmt.Errorf("the resource method: %s for url: %s is invalid", m, resource.URL)
			}
		}
	}

	return nil
}

// usage displays the usage menu and exits
func usage(cx *cli.Context, message string) {
	fmt.Fprintf(os.Stderr, "\n[error] %s\n", message)
	os.Exit(1)
}

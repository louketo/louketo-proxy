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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/codegangsta/cli"
)

// newDefaultConfig returns a initialized config
func newDefaultConfig() *Config {
	return &Config{
		TagData:     make(map[string]string, 0),
		ClaimsMatch: make(map[string]string, 0),
	}
}

// isValid validates if the config is valid
func (r *Config) isValid() error {
	// step: validate the configuration
	if r.Upstream == "" {
		return fmt.Errorf("you have not specified an upstream endpoint to proxy to")
	}
	if _, err := url.Parse(r.Upstream); err != nil {
		return fmt.Errorf("the upstream endpoint is invalid, %s", err)
	}
	if r.Listen == "" {
		return fmt.Errorf("you have not specified the listening interface")
	}
	if r.TLSCertificate != "" && r.TLSPrivateKey == "" {
		return fmt.Errorf("you have not provided a private key")
	}
	if r.TLSPrivateKey != "" && r.TLSCertificate == "" {
		return fmt.Errorf("you have not provided a certificate file")
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

	// step: if the skip verification is off, we need the below
	if !r.SkipTokenVerification {
		if r.DiscoveryURL == "" {
			return fmt.Errorf("you have not specified the discovery url")
		}
		if r.ClientID == "" {
			return fmt.Errorf("you have not specified the client id")
		}
		if r.Secret == "" {
			return fmt.Errorf("you have not specified the client secret")
		}
		if r.RedirectionURL == "" {
			return fmt.Errorf("you have not specified the redirection url")
		}
		if strings.HasSuffix(r.RedirectionURL, "/") {
			r.RedirectionURL = strings.TrimSuffix(r.RedirectionURL, "/")
		}
		if r.EncryptionKey == "" && r.RefreshSession {
			return fmt.Errorf("you have not specified a encryption key for encoding the session state")
		}
		if r.EncryptionKey != "" && len(r.EncryptionKey) < 32 {
			return fmt.Errorf("the encryption key is too short, must be longer than 32 characters")
		}
		if r.MaxSession == 0 && r.RefreshSession {
			r.MaxSession = time.Duration(6) * time.Hour
		}
	}
	for _, resource := range r.Resources {
		if err := resource.isValid(); err != nil {
			return err
		}
	}

	return nil
}

// hasSignInPage checks if there is a custom sign in  page
func (r *Config) hasSignInPage() bool {
	if r.SignInPage != "" {
		return true
	}

	return false
}

// hasForbiddenPage checks if there is a custom forbidden page
func (r *Config) hasForbiddenPage() bool {
	if r.ForbiddenPage != "" {
		return true
	}

	return false
}

// readOptions parses the command line options and constructs a config object
func readOptions(cx *cli.Context, config *Config) (err error) {
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
	if cx.IsSet("skip-token-verification") {
		config.SkipTokenVerification = cx.Bool("skip-token-verification")
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
	if cx.IsSet("tls-ca-certificate") {
		config.TLSCaCertificate = cx.String("tls-ca-certificate")
	}
	if cx.IsSet("signin-page") {
		config.SignInPage = cx.String("signin-page")
	}
	if cx.IsSet("forbidden-page") {
		config.ForbiddenPage = cx.String("forbidden-page")
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
	if cx.IsSet("verbose") {
		config.Verbose = cx.Bool("verbose")
	}
	if cx.IsSet("scope") {
		config.Scopes = cx.StringSlice("scope")
	}
	if cx.IsSet("hostname") {
		config.Hostnames = cx.StringSlice("hostname")
	}
	if cx.IsSet("tag") {
		config.TagData, err = decodeKeyPairs(cx.StringSlice("tag"))
		if err != nil {
			return err
		}
	}
	if cx.IsSet("claim") {
		config.ClaimsMatch, err = decodeKeyPairs(cx.StringSlice("claim"))
		if err != nil {
			return err
		}
	}
	if cx.IsSet("resource") {
		for _, x := range cx.StringSlice("resource") {
			resource, err := decodeResource(x)
			if err != nil {
				return fmt.Errorf("invalid resource %s, %s", x, err)
			}
			config.Resources = append(config.Resources, resource)
		}
	}

	return nil
}

// readConfigFile reads and parses the configuration file
func readConfigFile(filename string, config *Config) error {
	// step: read in the contents of the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	// step: attempt to un-marshal the data
	if isJson := filepath.Ext(filename) == "json"; isJson {
		err = json.Unmarshal(content, config)
	} else {
		err = yaml.Unmarshal(content, config)
	}
	if err != nil {
		return err
	}

	return nil
}

// getOptions returns the command line options
func getOptions() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Usage: "the path to the configuration file for the keycloak proxy",
		},
		cli.StringFlag{
			Name:  "listen",
			Usage: "the interface the service should be listening on",
			Value: "127.0.0.1:8080",
		},
		cli.StringFlag{
			Name:  "secret",
			Usage: "the client secret used to authenticate to the oauth server",
		},
		cli.StringFlag{
			Name:  "client-id",
			Usage: "the client id used to authenticate to the oauth serves",
		},
		cli.StringFlag{
			Name:  "discovery-url",
			Usage: "the discovery url to retrieve the openid configuration",
		},
		cli.StringFlag{
			Name:  "upstream-url",
			Usage: "the url for the upstream endpoint you wish to proxy to",
			Value: "http://127.0.0.1:8080",
		},
		cli.StringFlag{
			Name:  "encryption-key",
			Usage: "the encryption key used to encrpytion the session state",
		},
		cli.StringFlag{
			Name:  "redirection-url",
			Usage: "the redirection url, namely the site url, note: " + oauthURL + " will be added to it",
		},
		cli.StringSliceFlag{
			Name:  "hostname",
			Usage: "a list of hostname which the service will respond to, defaults to all",
		},
		cli.StringFlag{
			Name:  "tls-cert",
			Usage: "the path to a certificate file used for TLS",
		},
		cli.StringFlag{
			Name:  "tls-private-key",
			Usage: "the path to the private key for TLS support",
		},
		cli.StringFlag{
			Name:  "tls-ca-certificate",
			Usage: "the path to the ca certificate used for mutual TLS",
		},
		cli.StringSliceFlag{
			Name:  "scope",
			Usage: "a variable list of scopes requested when authenticating the user",
		},
		cli.StringSliceFlag{
			Name:  "claim",
			Usage: "a series of key pair values which must match the claims in the token present e.g. aud=myapp, iss=http://example.com etcd",
		},
		cli.StringSliceFlag{
			Name:  "resource",
			Usage: "a list of resources 'uri=/admin|methods=GET|roles=role1,role2'",
		},
		cli.StringFlag{
			Name:  "signin-page",
			Usage: "a custom template displayed for signin",
		},
		cli.StringFlag{
			Name:  "forbidden-page",
			Usage: "a custom template used for access forbidden",
		},
		cli.StringSliceFlag{
			Name:  "tag",
			Usage: "a keypair tag which is passed to the templates when render, i.e. title='My Page',site='my name' etc",
		},
		cli.DurationFlag{
			Name:  "max-session",
			Usage: "if refresh sessions are enabled we can limit their duration via this",
			Value: time.Duration(1) * time.Hour,
		},
		cli.BoolFlag{
			Name:  "skip-token-verification",
			Usage: "testing purposes ONLY, the option allows you to bypass the token verification, expiration and roles are still enforced",
		},
		cli.BoolFlag{
			Name:  "proxy-protocol",
			Usage: "switches on proxy protocol support on the listen (not supported yet)",
		},
		cli.BoolFlag{
			Name:  "refresh-sessions",
			Usage: "enables the refreshing of tokens via offline access",
		},
		cli.BoolTFlag{
			Name:  "json-logging",
			Usage: "switch on json logging rather than text (defaults true)",
		},
		cli.BoolTFlag{
			Name:  "log-requests",
			Usage: "switch on logging of all incoming requests (defaults true)",
		},
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "switch on debug / verbose logging",
		},
	}
}

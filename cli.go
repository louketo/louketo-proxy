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
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/urfave/cli"
)

//
// newOauthProxyApp creates a new cli application and runs it
//
func newOauthProxyApp() *cli.App {
	config := newDefaultConfig()

	// step: create the cli application
	app := cli.NewApp()
	app.Name = prog
	app.Usage = description
	app.Version = version
	app.Author = author
	app.Email = email
	app.Flags = getCLIOptions()
	app.UsageText = "keycloak-proxy [options]"

	// step: the standard usage message isn't that helpful
	app.OnUsageError = func(context *cli.Context, err error, isSubcommand bool) error {
		fmt.Fprintf(os.Stderr, "[error] invalid options, %s\n", err)
		return err
	}

	// step: set the default action
	app.Action = func(cx *cli.Context) error {
		configFile := cx.String("config")

		// step: do we have a configuration file?
		if configFile != "" {
			if err := readConfigFile(configFile, config); err != nil {
				return printError("unable to read the configuration file: %s, error: %s", configFile, err.Error())
			}
		}

		// step: parse the command line options
		if err := parseCLIOptions(cx, config); err != nil {
			return printError(err.Error())
		}

		// step: validate the configuration
		if err := config.isValid(); err != nil {
			return printError(err.Error())
		}

		// step: create the proxy
		proxy, err := newProxy(config)
		if err != nil {
			return printError(err.Error())
		}

		// step: start the service
		if err := proxy.Run(); err != nil {
			return printError(err.Error())
		}

		// step: setup the termination signals
		signalChannel := make(chan os.Signal)
		signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		<-signalChannel

		return nil
	}

	return app
}

// getCLIOptions returns the command line options
func getCLIOptions() []cli.Flag {
	defaults := newDefaultConfig()
	return []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Usage:  "the path to the configuration file for the keycloak proxy",
			EnvVar: "PROXY_CONFIG_FILE",
		},
		cli.StringFlag{
			Name:   "listen",
			Usage:  "the interface the service should be listening on",
			Value:  defaults.Listen,
			EnvVar: "PROXY_LISTEN",
		},
		cli.StringFlag{
			Name:   "listen-http",
			Usage:  "the interface you want the http-only service to use on",
			EnvVar: "PROXY_HTTP_LISTEN",
		},
		cli.StringFlag{
			Name:   "discovery-url",
			Usage:  "the discovery url to retrieve the openid configuration",
			EnvVar: "PROXY_DISCOVERY_URL",
		},
		cli.StringFlag{
			Name:   "client-secret",
			Usage:  "the client secret used to authenticate to the oauth server (access_type: confidential)",
			EnvVar: "PROXY_CLIENT_SECRET",
		},
		cli.StringFlag{
			Name:   "client-id",
			Usage:  "the client id used to authenticate to the oauth service",
			EnvVar: "PROXY_CLIENT_ID",
		},
		cli.StringSliceFlag{
			Name:  "scopes",
			Usage: "a variable list of scopes requested when authenticating the user",
		},
		cli.BoolFlag{
			Name:  "token-validate-only",
			Usage: "validate the token and roles only, no required implement oauth",
		},
		cli.StringFlag{
			Name:   "redirection-url",
			Usage:  fmt.Sprintf("redirection url for the oauth callback url (%s is added)", oauthURL),
			EnvVar: "PROXY_REDIRECTION_URL",
		},
		cli.StringFlag{
			Name:   "revocation-url",
			Usage:  "the url for the revocation endpoint to revoke refresh token",
			EnvVar: "PROXY_REVOCATION_URL",
		},
		cli.StringFlag{
			Name:   "store-url",
			Usage:  "url for the storage subsystem, e.g redis://127.0.0.1:6379, file:///etc/tokens.file",
			EnvVar: "PROXY_STORE_URL",
		},
		cli.StringFlag{
			Name:   "upstream-url",
			Usage:  "the url for the upstream endpoint you wish to proxy to",
			Value:  defaults.Upstream,
			EnvVar: "PROXY_UPSTREAM_URL",
		},
		cli.BoolTFlag{
			Name:  "upstream-keepalives",
			Usage: "enables or disables the keepalive connections for upstream endpoint",
		},
		cli.DurationFlag{
			Name:  "upstream-timeout",
			Usage: "is the maximum amount of time a dial will wait for a connect to complete",
			Value: defaults.UpstreamTimeout,
		},
		cli.DurationFlag{
			Name:  "upstream-keepalive-timeout",
			Usage: "specifies the keep-alive period for an active network connection",
			Value: defaults.UpstreamKeepaliveTimeout,
		},
		cli.BoolTFlag{
			Name:  "secure-cookie",
			Usage: "enforces the cookie to be secure, default to true",
		},
		cli.BoolFlag{
			Name:  "http-only-cookie",
			Usage: "enforces the cookie is in http only mode, default to false",
		},
		cli.StringFlag{
			Name:  "cookie-domain",
			Usage: "a domain the access cookie is available to, defaults host header",
		},
		cli.StringFlag{
			Name:  "cookie-access-name",
			Usage: "the name of the cookie use to hold the access token",
			Value: defaults.CookieAccessName,
		},
		cli.StringFlag{
			Name:  "cookie-refresh-name",
			Usage: "the name of the cookie used to hold the encrypted refresh token",
			Value: defaults.CookieRefreshName,
		},
		cli.StringFlag{
			Name:  "encryption-key",
			Usage: "the encryption key used to encrpytion the session state",
		},
		cli.BoolFlag{
			Name:  "no-redirects",
			Usage: "do not have back redirects when no authentication is present, 401 them",
		},
		cli.StringSliceFlag{
			Name:  "hostname",
			Usage: "a list of hostnames the service will respond to, defaults to all",
		},
		cli.BoolFlag{
			Name:  "enable-login-handler",
			Usage: "this enables the login hanlder /oauth/login, by default this is disabled",
		},
		cli.BoolTFlag{
			Name:  "enable-authorization-header",
			Usage: "adds the authorization header to the proxy request",
		},
		cli.BoolTFlag{
			Name:  "enable-refresh-tokens",
			Usage: "enables the handling of the refresh tokens",
		},
		cli.BoolTFlag{
			Name:  "enable-metrics",
			Usage: "enable the prometheus metrics collector on /oauth/metrics",
		},
		cli.BoolTFlag{
			Name:  "localhost-only-metrics",
			Usage: "enforces the metrics page can only been requested from 127.0.0.1",
		},
		cli.BoolFlag{
			Name:  "enable-proxy-protocol",
			Usage: "whether to enable proxy protocol",
		},
		cli.BoolFlag{
			Name:  "enable-forwarding",
			Usage: "enables the forwarding proxy mode, signing outbound request",
		},
		cli.BoolTFlag{
			Name:  "enable-profiling",
			Usage: "switching on the golang profiling via pprof on /debug/pprof, /debug/pprof/heap etc",
		},
		cli.BoolTFlag{
			Name:  "enable-security-filter",
			Usage: "enables the security filter handler",
		},
		cli.StringFlag{
			Name:  "forwarding-username",
			Usage: "the username to use when logging into the openid provider",
		},
		cli.StringFlag{
			Name:  "forwarding-password",
			Usage: "the password to use when logging into the openid provider",
		},
		cli.StringSliceFlag{
			Name:  "forwarding-domains",
			Usage: "a list of domains which should be signed; everything else is relayed unsigned",
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
		cli.StringFlag{
			Name:  "tls-ca-key",
			Usage: "the path the ca private key, used by the forward signing proxy",
		},
		cli.StringFlag{
			Name:  "tls-client-certificate",
			Usage: "the path to the client certificate, used to outbound connections in reverse and forwarding proxy modes",
		},
		cli.BoolTFlag{
			Name:  "skip-upstream-tls-verify",
			Usage: "whether to skip the verification of any upstream TLS (defaults to true)",
		},
		cli.BoolTFlag{
			Name:  "skip-openid-provider-tls-verify",
			Usage: "whether to skip the verification of any TLS communication with the openid provider (defaults to false)",
		},
		cli.StringSliceFlag{
			Name:  "match-claims",
			Usage: "keypair values for matching access token claims e.g. aud=myapp, iss=http://example.*",
		},
		cli.StringSliceFlag{
			Name:  "add-claims",
			Usage: "retrieve extra claims from the token and inject into headers, e.g given_name -> X-Auth-Given-Name",
		},
		cli.StringSliceFlag{
			Name:  "resource",
			Usage: "a list of resources 'uri=/admin|methods=GET,PUT|roles=role1,role2'",
		},
		cli.StringSliceFlag{
			Name:  "headers",
			Usage: "Add custom headers to the upstream request, key=value",
		},
		cli.StringFlag{
			Name:  "sign-in-page",
			Usage: "a custom template displayed for signin",
		},
		cli.StringFlag{
			Name:  "forbidden-page",
			Usage: "a custom template used for access forbidden",
		},
		cli.StringSliceFlag{
			Name:  "tag",
			Usage: "keypair's passed to the templates at render,e.g title='My Page'",
		},
		cli.StringSliceFlag{
			Name:  "cors-origins",
			Usage: "list of origins to add to the CORE origins control (Access-Control-Allow-Origin)",
		},
		cli.StringSliceFlag{
			Name:  "cors-methods",
			Usage: "the method permitted in the access control (Access-Control-Allow-Methods)",
		},
		cli.StringSliceFlag{
			Name:  "cors-headers",
			Usage: "a set of headers to add to the CORS access control (Access-Control-Allow-Headers)",
		},
		cli.StringSliceFlag{
			Name:  "cors-exposes-headers",
			Usage: "set the expose cors headers access control (Access-Control-Expose-Headers)",
		},
		cli.DurationFlag{
			Name:  "cors-max-age",
			Usage: "the max age applied to cors headers (Access-Control-Max-Age)",
		},
		cli.BoolTFlag{
			Name:  "cors-credentials",
			Usage: "the credentials access control header (Access-Control-Allow-Credentials)",
		},
		cli.BoolTFlag{
			Name:  "filter-browser-xss",
			Usage: "enable the adds the X-XSS-Protection header with mode=block",
		},
		cli.BoolTFlag{
			Name:  "filter-content-nosniff",
			Usage: "adds the X-Content-Type-Options header with the value nosniff",
		},
		cli.BoolFlag{
			Name:  "skip-token-verification",
			Usage: "TESTING ONLY; bypass token verification, only expiration and roles enforced",
		},
		cli.BoolTFlag{
			Name:  "json-logging",
			Usage: "switch on json logging rather than text (defaults true)",
		},
		cli.BoolTFlag{
			Name:  "log-requests",
			Usage: "switch on logging of all incoming requests (defaults true)",
		},
		cli.BoolTFlag{
			Name:  "verbose",
			Usage: "switch on debug / verbose logging",
		},
	}
}

//
// parseCLIOptions parses the command line options and constructs a config object
// @TODO look for a shorter way of doing this, we're maintaining the same options in multiple places, it's tedious!
//
func parseCLIOptions(cx *cli.Context, config *Config) (err error) {
	// step: we can ignore these options in the Config struct
	ignoredOptions := []string{"tag-data", "match-claims", "resources", "headers"}
	// step: iterate the Config and grab command line options via reflection
	count := reflect.TypeOf(config).Elem().NumField()
	for i := 0; i < count; i++ {
		field := reflect.TypeOf(config).Elem().Field(i)
		name := field.Tag.Get("yaml")
		if containedIn(name, ignoredOptions) {
			continue
		}

		if cx.IsSet(name) {
			switch field.Type.Kind() {
			case reflect.Bool:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).SetBool(cx.Bool(name))
			case reflect.String:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).SetString(cx.String(name))
			case reflect.Slice:
				for _, x := range cx.StringSlice(name) {
					reflect.Append(reflect.ValueOf(config).Elem().FieldByName(field.Name), reflect.ValueOf(x))
				}
			}
		}
	}
	if cx.IsSet("tag") {
		tags, err := decodeKeyPairs(cx.StringSlice("tag"))
		if err != nil {
			return err
		}
		mergeMaps(config.TagData, tags)
	}
	if cx.IsSet("match-claims") {
		claims, err := decodeKeyPairs(cx.StringSlice("match-claims"))
		if err != nil {
			return err
		}
		mergeMaps(config.MatchClaims, claims)
	}
	if cx.IsSet("headers") {
		headers, err := decodeKeyPairs(cx.StringSlice("headers"))
		if err != nil {
			return err
		}
		mergeMaps(config.Headers, headers)
	}
	if cx.IsSet("resource") {
		for _, x := range cx.StringSlice("resource") {
			resource, err := newResource().parse(x)
			if err != nil {
				return fmt.Errorf("invalid resource %s, %s", x, err)
			}
			config.Resources = append(config.Resources, resource)
		}
	}

	return nil
}

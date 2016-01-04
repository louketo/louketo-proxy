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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codegangsta/cli"
)

func main() {
	// step: create the applications
	kc := cli.NewApp()
	kc.Name = prog
	kc.Usage = "is a proxy using the keycloak service for auth and authorization"
	kc.Version = version
	kc.Author = author
	kc.Email = email
	kc.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Usage: "the path to the configuration file for the keycloak proxy",
		},
		cli.StringFlag{
			Name:  "listen",
			Usage: "the interface the service should be listening on",
			Value: "127.0.0.1:80",
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
		cli.StringFlag{
			Name:  "tls-cert",
			Usage: "the path to a certificate file used for enabled TLS for the service",
		},
		cli.StringFlag{
			Name:  "tls-private-key",
			Usage: "the path to the private key for TLS support",
		},
		cli.StringSliceFlag{
			Name:  "scope",
			Usage: "a variable list of scopes requested when authenticating the user",
		},
		cli.StringSliceFlag{
			Name:  "resource",
			Usage: "a list of resources 'uri=/admin|methods=GET|roles=role1,role2",
		},
		cli.StringFlag{
			Name:  "signin-page",
			Usage: "a custom template under ./templates displayed for signin",
		},
		cli.StringFlag{
			Name:  "forbidden-page",
			Usage: "a custom template under ./templates used for access forbidden",
		},
		cli.DurationFlag{
			Name:  "max-session",
			Usage: "if refresh sessions are enabled we can limit their duration via this",
			Value: time.Duration(1) * time.Hour,
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
	// the default action
	kc.Action = func(cx *cli.Context) {
		// step: parse the configuration
		config, err := parseConfig(cx)
		if err != nil {
			usage(cx, err.Error())
		}
		// step: validate the configuration
		if err := validateConfig(config); err != nil {
			usage(cx, err.Error())
		}
		// step: create the proxy
		proxy, err := NewKeycloakProxy(config)
		if err != nil {
			usage(cx, err.Error())
		}
		// step: start running the service
		if err := proxy.Run(); err != nil {
			usage(cx, err.Error())
		}

		// step: setup the termination signals
		signalChannel := make(chan os.Signal)
		signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		<-signalChannel
	}

	kc.Run(os.Args)
}

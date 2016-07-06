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
	"syscall"

	"github.com/urfave/cli"
)

func newOauthProxyApp() *cli.App {
	// step: grab the default configuration
	config := newDefaultConfig()

	// step: create the cli application
	app := cli.NewApp()
	app.Name = prog
	app.Usage = description
	app.Version = version
	app.Author = author
	app.Email = email
	app.Flags = getOptions()
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
		if err := readOptions(cx, config); err != nil {
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

// printError display the command line usage and error
func printError(message string, args ...interface{}) *cli.ExitError {
	return cli.NewExitError(fmt.Sprintf("[error] "+message, args...), 1)
}

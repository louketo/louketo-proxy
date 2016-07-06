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

func main() {
	config := newDefaultConfig()
	kc := cli.NewApp()
	kc.Name = prog
	kc.Usage = description
	kc.Version = version
	kc.Author = author
	kc.Email = email
	kc.UsageText = "keycloak-proxy [options]"
	kc.Flags = getOptions()
	kc.Action = func(cx *cli.Context) error {
		// step: do we have a configuration file?
		if filename := cx.String("config"); filename != "" {
			if err := readConfigFile(filename, config); err != nil {
				return printError("unable to read the configuration file: %s, error: %s", filename, err.Error())
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
	kc.Run(os.Args)
}

// printUsage display the command line usage and error
func printError(message string, args ...interface{}) *cli.ExitError {
	return cli.NewExitError(fmt.Sprintf("[error] "+message, args...), 1)
}

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

	"github.com/codegangsta/cli"
)

func main() {
	// step: the proxy configuration
	config := newDefaultConfig()

	// step: construct the application
	kc := cli.NewApp()
	kc.Name = prog
	kc.Usage = description
	kc.Version = version
	kc.Author = author
	kc.Email = email
	kc.Flags = getOptions()
	// the default actions
	kc.Action = func(cx *cli.Context) {
		// do we have a configuration file?
		if filename := cx.String("config"); filename != "" {
			if err := readConfigFile(cx.String("config"), config); err != nil {
				printUsage(err.Error())
			}
		}
		// parse the command line options
		if err := readOptions(cx, config); err != nil {
			printUsage(err.Error())
		}
		// step: validate the configuration
		if err := config.isValid(); err != nil {
			printUsage(err.Error())
		}
		// step: create the proxy
		proxy, err := newKeycloakProxy(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s", err)
			os.Exit(1)
		}
		// step: start the service
		if err := proxy.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s", err)
			os.Exit(1)
		}
		// step: setup the termination signals
		signalChannel := make(chan os.Signal)
		signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		<-signalChannel
	}

	kc.Run(os.Args)
}

// printUsage display the command line usage and error
func printUsage(message string) {
	fmt.Fprintf(os.Stderr, "[error] %s\n", message)
	os.Exit(1)
}

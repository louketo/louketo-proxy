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
	config := newDefaultConfig()
	kc := cli.NewApp()
	kc.Name = prog
	kc.Usage = description
	kc.Version = version
	kc.Author = author
	kc.Email = email
	kc.Flags = getOptions()
	kc.Action = func(cx *cli.Context) {
		// step: do we have a configuration file?
		if filename := cx.String("config"); filename != "" {
			if err := readConfigFile(filename, config); err != nil {
				printUsage(fmt.Sprintf("unable to read the configuration file: %s, error: %s", filename, err.Error()))
			}
		}
		// step: parse the command line options
		if err := readOptions(cx, config); err != nil {
			printUsage(err.Error())
		}
		// step: validate the configuration
		if err := config.isValid(); err != nil {
			printUsage(err.Error())
		}
		// step: create the proxy
		proxy, err := newProxy(config)
		if err != nil {
			printUsage(err.Error())
		}
		// step: start the service
		if err := proxy.Run(); err != nil {
			printUsage(err.Error())
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
	fmt.Fprintf(os.Stderr, "\n[error] %s\n", message)
	os.Exit(1)
}

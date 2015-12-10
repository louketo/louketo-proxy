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
	"os"
	"os/signal"
	"syscall"
)

func main() {
	flag.Parse()

	// step: get the configuration
	config, err := parseConfig(cfgFilename)
	if err != nil {
		usage(err.Error())
	}

	// step: create the proxy
	proxy, err := NewProxy(config)
	if err != nil {
		usage(err.Error())
	}

	// step: start running the service
	if err := proxy.Run(); err != nil {
		usage(err.Error())
	}

	// step: setup the termination signals
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	<-signalChannel
}

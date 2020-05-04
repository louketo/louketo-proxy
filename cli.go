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
	"time"

	"github.com/urfave/cli"
)

const durationType = "time.Duration"

// newOauthProxyApp creates a new cli application and runs it
func newOauthProxyApp() *cli.App {
	config := newDefaultConfig()
	app := cli.NewApp()
	app.Name = prog
	app.Usage = description
	app.Version = getVersion()
	app.Author = author
	app.Email = email
	app.Flags = getCommandLineOptions()
	app.UsageText = "louketo-proxy [options]"

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
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		<-signalChannel

		return nil
	}

	return app
}

// getCommandLineOptions builds the command line options by reflecting the Config struct and extracting
// the tagged information
func getCommandLineOptions() []cli.Flag {
	defaults := newDefaultConfig()
	var flags []cli.Flag
	count := reflect.TypeOf(Config{}).NumField()
	for i := 0; i < count; i++ {
		field := reflect.TypeOf(Config{}).Field(i)
		usage, found := field.Tag.Lookup("usage")
		if !found {
			continue
		}
		envName := field.Tag.Get("env")
		if envName != "" {
			envName = envPrefix + envName
		}
		optName := field.Tag.Get("yaml")

		switch t := field.Type; t.Kind() {
		case reflect.Bool:
			dv := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).Bool()
			msg := fmt.Sprintf("%s (default: %t)", usage, dv)
			flags = append(flags, cli.BoolTFlag{
				Name:   optName,
				Usage:  msg,
				EnvVar: envName,
			})
		case reflect.String:
			defaultValue := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).String()
			flags = append(flags, cli.StringFlag{
				Name:   optName,
				Usage:  usage,
				EnvVar: envName,
				Value:  defaultValue,
			})
		case reflect.Slice:
			fallthrough
		case reflect.Map:
			flags = append(flags, cli.StringSliceFlag{
				Name:  optName,
				Usage: usage,
			})
		case reflect.Int:
			flags = append(flags, cli.IntFlag{
				Name:   optName,
				Usage:  usage,
				EnvVar: envName,
			})
		case reflect.Int64:
			switch t.String() {
			case durationType:
				dv := reflect.ValueOf(defaults).Elem().FieldByName(field.Name).Int()
				flags = append(flags, cli.DurationFlag{
					Name:  optName,
					Usage: usage,
					Value: time.Duration(dv),
				})
			default:
				panic("unknown uint64 type in the Config struct")
			}
		default:
			errMsg := fmt.Sprintf("field: %s, type: %s, kind: %s is not being handled", field.Name, t.String(), t.Kind())
			panic(errMsg)
		}
	}

	return flags
}

// parseCLIOptions parses the command line options and constructs a config object
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
				reflect.ValueOf(config).Elem().FieldByName(field.Name).Set(reflect.ValueOf(cx.StringSlice(name)))
			case reflect.Int:
				reflect.ValueOf(config).Elem().FieldByName(field.Name).Set(reflect.ValueOf(cx.Int(name)))
			case reflect.Int64:
				switch field.Type.String() {
				case durationType:
					reflect.ValueOf(config).Elem().FieldByName(field.Name).SetInt(int64(cx.Duration(name)))
				default:
					reflect.ValueOf(config).Elem().FieldByName(field.Name).SetInt(cx.Int64(name))
				}
			}
		}
	}
	if cx.IsSet("tag") {
		tags, err := decodeKeyPairs(cx.StringSlice("tag"))
		if err != nil {
			return err
		}
		mergeMaps(config.Tags, tags)
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
	if cx.IsSet("resources") {
		for _, x := range cx.StringSlice("resources") {
			resource, err := newResource().parse(x)
			if err != nil {
				return fmt.Errorf("invalid resource %s, %s", x, err)
			}
			config.Resources = append(config.Resources, resource)
		}
	}

	return nil
}

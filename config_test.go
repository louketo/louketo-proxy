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
	"io/ioutil"
	"os"
	"testing"

	"github.com/codegangsta/cli"
)

func TestNewDefaultConfig(t *testing.T) {
	if config := newDefaultConfig(); config == nil {
		t.Errorf("we should have recieved a config")
	}
}

func TestReadConfiguration(t *testing.T) {
	testCases := []struct {
		Content string
		Ok      bool
	}{
		{
			Content: `
discovery_url: https://keyclock.domain.com/
client-id: <client_id>
secret: <secret>
`,
		},
		{
			Content: `
discovery_url: https://keyclock.domain.com
client-id: <client_id>
secret: <secret>
upstream: http://127.0.0.1:8080
redirection_url: http://127.0.0.1:3000
`,
			Ok: true,
		},
	}

	for i, test := range testCases {
		// step: write the fake config file
		file := writeFakeConfigFile(t, test.Content)
		defer func(f *os.File) {
			os.Remove(f.Name())
		}(file)

		config := new(Config)
		err := readConfigFile(file.Name(), config)
		if test.Ok && err != nil {
			t.Errorf("test case %d should not have failed, config: %v, error: %s", i, config, err)
		}
	}
}

func TestIsConfig(t *testing.T) {
	tests := []struct {
		Config *Config
		Ok     bool
	}{
		{
			Config: &Config{},
		},
		{
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8080",
			},
		},
		{
			Config: &Config{
				DiscoveryURL: "http://127.0.0.1:8080",
				ClientID:     "client",
				ClientSecret: "client",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
			},
			Ok: true,
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
				ClaimsMatch: map[string]string{
					"test": "&&&[",
				},
			},
		},
		{
			Config: &Config{
				Listen:                ":8080",
				SkipTokenVerification: true,
				Upstream:              "http://120.0.0.1",
			},
			Ok: true,
		},
		{
			Config: &Config{
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
			},
		},
		{
			Config: &Config{
				Listen:         ":8080",
				DiscoveryURL:   "http://127.0.0.1:8080",
				ClientID:       "client",
				ClientSecret:   "client",
				RedirectionURL: "http://120.0.0.1",
				Upstream:       "this should fail",
			},
		},
	}

	for i, c := range tests {
		if err := c.Config.isValid(); err != nil && c.Ok {
			t.Errorf("test case %d, the config should not have errored, error: %s", i, err)
		}
	}
}

func TestReadOptions(t *testing.T) {
	c := cli.NewApp()
	c.Flags = getOptions()
	c.Action = func(cx *cli.Context) {
		readOptions(cx, &Config{})
	}
	c.Run([]string{""})
}

func TestGetOptions(t *testing.T) {
	if flags := getOptions(); flags == nil {
		t.Errorf("we should have received some flags options")
	}
}

func writeFakeConfigFile(t *testing.T, content string) *os.File {
	f, err := ioutil.TempFile("", "node_label_file")
	if err != nil {
		t.Fatalf("unexpected error creating node_label_file: %v", err)
	}
	f.Close()

	if err := ioutil.WriteFile(f.Name(), []byte(content), 0700); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return f
}

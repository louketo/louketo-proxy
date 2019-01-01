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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestNewOauthProxyApp(t *testing.T) {
	a := newOauthProxyApp()
	assert.NotNil(t, a)
}

func TestGetCLIOptions(t *testing.T) {
	if flags := getCommandLineOptions(); flags == nil {
		t.Error("we should have received some flags options")
	}
}

func TestReadOptions(t *testing.T) {
	c := cli.NewApp()
	c.Flags = getCommandLineOptions()
	c.Action = func(cx *cli.Context) error {
		ero := parseCLIOptions(cx, &Config{})
		assert.NoError(t, ero)
		return nil
	}
	err := c.Run([]string{""})
	assert.NoError(t, err)
}

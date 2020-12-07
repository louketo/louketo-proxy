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
	"reflect"
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

type cliOption struct {
	OptionName string
	FieldValue reflect.Value
}

func TestParseCLIMapOptions(t *testing.T) {
	config := newDefaultConfig()
	c := cli.NewApp()
	c.Flags = getCommandLineOptions()
	c.Action = func(cx *cli.Context) error {
		ero := parseCLIOptions(cx, config)
		assert.NoError(t, ero)
		return nil
	}
	mapOptions := []cliOption{}
	command := []string{"test-cmd"}
	resultMap := make(map[string]string)
	configPropCount := reflect.TypeOf(config).Elem().NumField()
	for i := 0; i < configPropCount; i++ {
		field := reflect.TypeOf(config).Elem().Field(i)
		if field.Type.Kind() == reflect.Map {
			name := field.Tag.Get("yaml")
			option := cliOption{
				OptionName: name,
				FieldValue: reflect.ValueOf(config).Elem().FieldByName(field.Name),
			}
			mapOptions = append(mapOptions, option)
			resultMap[fmt.Sprintf("%s:%s", name, "k1")] = "v1"
			resultMap[fmt.Sprintf("%s:%s", name, "k2")] = "v2=testEqualChar"
			command = append(command, fmt.Sprintf("--%s=k1=v1", name))
			command = append(command, fmt.Sprintf("--%s=k2=v2=testEqualChar", name))
		}
	}
	err := c.Run(command)
	assert.NoError(t, err)
	errFmt := "the parsed %s cli option is not correct"
	for i := 0; i < len(mapOptions); i++ {
		name := mapOptions[i].OptionName
		fieldValue := mapOptions[i].FieldValue
		keys := fieldValue.MapKeys()
		assert.True(t, len(keys) > 0, "we should have received flags for all map options")
		for j := 0; j < len(keys); j++ {
			expected := resultMap[fmt.Sprintf("%s:%s", name, keys[j].String())]
			actual := fieldValue.MapIndex(keys[j]).String()
			assert.Equal(t, expected, actual, fmt.Sprintf(errFmt, name))
		}
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

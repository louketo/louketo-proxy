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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateStorageRedis(t *testing.T) {
	store, err := createStorage("redis://127.0.0.1")
	assert.NotNil(t, store)
	assert.NoError(t, err)
}

func TestCreateStorageBoltDB(t *testing.T) {
	store, err := createStorage("boltdb:////tmp/bolt")
	assert.NotNil(t, store)
	assert.NoError(t, err)
	if store != nil {
		os.Remove("/tmp/bolt")
	}
}

func TestCreateStorageFail(t *testing.T) {
	store, err := createStorage("not_there:///tmp/bolt")
	assert.Nil(t, store)
	assert.Error(t, err)
}

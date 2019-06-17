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

/*
// deprecated upgrade: WebSocket connection upgrade is natively supported by stdlib reverse proxy
import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDialAddress(t *testing.T) {
	assert.Equal(t, dialAddress(getFakeURL("http://127.0.0.1")), "127.0.0.1:80")
	assert.Equal(t, dialAddress(getFakeURL("https://127.0.0.1")), "127.0.0.1:443")
	assert.Equal(t, dialAddress(getFakeURL("http://127.0.0.1:8080")), "127.0.0.1:8080")
}

func TestIsUpgradedConnection(t *testing.T) {
	header := http.Header{}
	header.Add(headerUpgrade, "")
	assert.False(t, isUpgradedConnection(&http.Request{Header: header}))
	header.Set(headerUpgrade, "set")
	assert.True(t, isUpgradedConnection(&http.Request{Header: header}))
}

func getFakeURL(location string) *url.URL {
	u, _ := url.Parse(location)
	return u
}

*/

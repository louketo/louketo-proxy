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
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

//TestWebSocket is used to validate that the proxy reverse proxy WebSocket connections.
func TestWebSocket(t *testing.T) {
	// Setup an upstream service.
	upstream := &fakeUpstreamService{}

	upstreamService := httptest.NewServer(upstream)
	defer upstreamService.Close()

	upstreamURL := upstreamService.URL

	// Setup the proxy.
	c := newFakeKeycloakConfig()
	c.Upstream = upstreamURL

	_, proxyServer, proxyURL := newTestProxyService(c)
	defer proxyServer.Close()

	proxyWsURL, err := url.Parse(proxyURL)
	require.NoError(t, err)

	proxyWsURL.Scheme = "ws"

	ws, err := websocket.Dial(proxyWsURL.String()+"/auth_all/white_listed/ws", "", "http://localhost/")
	require.NoError(t, err)

	request := []byte("hello, world!")
	err = websocket.Message.Send(ws, request)
	require.NoError(t, err)

	var responseData = make([]byte, 1024)
	err = websocket.Message.Receive(ws, &responseData)
	require.NoError(t, err)

	responseJSON := fakeUpstreamResponse{}
	err = json.Unmarshal(responseData, &responseJSON)
	require.NoError(t, err)

	assert.Equal(t, "/auth_all/white_listed/ws", responseJSON.URI)
}

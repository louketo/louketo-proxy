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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	e2eWSTLSUpstreamProxyListener = "gatekeeper.localtest.me:21328"

	e2eWSTLSUpstreamOauthListener    = "auth.localtest.me:11455"
	e2eWSTLSUpstreamUpstreamListener = "upstream.localtest.me:14511"
	e2eWSTLSUpstreamAppListener      = "app.localtest.me:7995"

	e2eWSTLSUpstreamAppURL      = "/ok"
	e2eWSTLSUpstreamUpstreamURL = "/echo"
)

var upgrader = websocket.Upgrader{} // use default options

func runTestWSTLSUpstream(t *testing.T, listener, route string) error {
	const health = "health"
	go func() {
		upstreamHandler := func(w http.ResponseWriter, req *http.Request) {
			// dump, _ := httputil.DumpRequest(req, false)
			// t.Logf("upstream received: %q", string(dump))
			c, err := upgrader.Upgrade(w, req, nil)
			if err != nil {
				t.Logf("server upgrade error: %v", err)
				t.Fail()
				return
			}
			defer c.Close()
			for {
				mt, message, err := c.ReadMessage()
				if err != nil {
					if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
						t.Logf("server ack client bailed. OK")
					} else {
						t.Logf("server read error: %v", err)
						t.Fail()
					}
					break
				}
				t.Logf("server recv: %s", message)
				err = c.WriteMessage(mt, message)
				if err != nil {
					t.Logf("server write error: %v", err)
					t.Fail()
					break
				}
			}
		}
		http.HandleFunc(route, upstreamHandler)
		http.HandleFunc("/"+health, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok"}`))
		})
		_ = http.ListenAndServeTLS(listener, upstreamCert, upstreamKey, nil)
	}()
	if !assert.True(t, checkListenOrBail("https://"+path.Join(listener, health))) {
		err := fmt.Errorf("cannot connect to test https listener on: %s", "https://"+path.Join(listener, health))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	t.Logf("test WS/TLS upstream server: %s%s", listener, route)
	return nil
}

/*
func runTestWSTLSApp(t *testing.T, listener, route string) error {
	go func() {
		mux := http.NewServeMux()
		appHandler := func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"message": "ok"}`)
			w.Header().Set("Content-Type", "application/json")
		}
		mux.HandleFunc(route, appHandler)
		_ = http.ListenAndServeTLS(listener, appCert, appKey, mux)
	}()
	if !assert.True(t, checkListenOrBail("https://"+path.Join(listener, route))) {
		err := fmt.Errorf("cannot connect to test https listener on: %s", "https://"+path.Join(listener, route))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	t.Logf("test WS/TLS app server: %s%s", listener, route)
	return nil
}
*/

// nolint: dupl
func runTestWSTLSAuth(t *testing.T, listener, realm string) error {
	// a stub OIDC provider
	fake := newFakeAuthServer()
	fake.location, _ = url.Parse("https://" + listener)

	issuer := "https://" + listener + path.Join("/auth", "realms", realm)
	discoveryURL := testDiscoveryPath(realm)
	authorizeURL := path.Join("/auth", "realms", realm, "protocol", "openid-connect", "auth")
	// #nosec
	tokenURL := path.Join("/auth", "realms", realm, "protocol", "openid-connect", "token")
	jwksURL := path.Join("/auth", "realms", realm, "protocol", "openid-connect", "certs")

	go func() {
		mux := http.NewServeMux()
		configurationHandler := func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"issuer": "`+issuer+`",
				"subject_types_supported":["public","pairwise"],
				"id_token_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512"],
				"userinfo_signing_alg_values_supported":["ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","RS512","none"],
				"authorization_endpoint":"https://`+listener+authorizeURL+`",
				"token_endpoint":"https://`+listener+tokenURL+`",
				"jwks_uri":"https://`+listener+jwksURL+`"
			}`)
		}
		authorizeHandler := func(w http.ResponseWriter, req *http.Request) {
			redirect := req.FormValue("redirect_uri")
			state := req.FormValue("state")
			code := "zzz"
			location, _ := url.PathUnescape(redirect)
			u, _ := url.Parse(location)
			v := u.Query()
			v.Set("code", code)
			v.Set("state", state)
			u.RawQuery = v.Encode()
			http.Redirect(w, req, u.String(), http.StatusFound)
		}

		tokenHandler := func(w http.ResponseWriter, req *http.Request) {
			fake.tokenHandler(w, req)
		}

		keysHandler := func(w http.ResponseWriter, req *http.Request) {
			fake.keysHandler(w, req)
		}
		mux.HandleFunc(discoveryURL, configurationHandler)
		mux.HandleFunc(authorizeURL, authorizeHandler)
		mux.HandleFunc(tokenURL, tokenHandler)
		mux.HandleFunc(jwksURL, keysHandler)
		_ = http.ListenAndServeTLS(listener, authCert, authKey, mux)
	}()
	if !assert.True(t, checkListenOrBail("https://"+path.Join(listener, jwksURL))) {
		err := fmt.Errorf("cannot connect to test https listener on: %s", "https://"+path.Join(listener, jwksURL))
		t.Logf("%v", err)
		t.FailNow()
		return err
	}
	t.Logf("test TLS auth server: %s [%s]", listener, realm)
	return nil
}

func testBuildWSTLSUpstreamConfig() *Config {
	config := newDefaultConfig()
	config.Verbose = true
	config.EnableLogging = true
	config.DisableAllLogging = false

	config.Listen = e2eWSTLSUpstreamProxyListener
	config.ListenHTTP = ""
	config.DiscoveryURL = testTLSDiscoveryURL(e2eWSTLSUpstreamOauthListener, "hod-test")
	// config.SkipOpenIDProviderTLSVerify = true
	config.OpenIDProviderCA = caCert

	config.Upstream = "https://" + e2eWSTLSUpstreamUpstreamListener

	config.TLSCertificate = gkCert
	config.TLSPrivateKey = gkKey
	config.SkipUpstreamTLSVerify = false
	config.UpstreamCA = caCert
	config.TLSUseModernSettings = true

	config.CorsOrigins = []string{"*"}
	config.EnableCSRF = false
	config.HTTPOnlyCookie = false // since we want to inspect the cookie for testing
	config.SecureCookie = true
	config.AccessTokenDuration = 30 * time.Minute
	config.EnableEncryptedToken = false
	config.EnableSessionCookies = true
	config.EnableAuthorizationCookies = false
	config.EnableClaimsHeaders = false
	config.EnableTokenHeader = false
	config.EnableAuthorizationHeader = true
	config.ClientID = fakeClientID
	config.ClientSecret = fakeSecret
	config.Resources = []*Resource{
		{
			URL:         "/echo",
			Methods:     []string{"GET", "POST", "DELETE"},
			WhiteListed: false,
			EnableCSRF:  false,
			Upstream:    "https://" + e2eWSTLSUpstreamUpstreamListener,
		},
	}
	config.EncryptionKey = secretForCookie
	return config
}

func TestWSTLSUpstream(t *testing.T) {
	// log.SetOutput(ioutil.Discard)

	config := testBuildWSTLSUpstreamConfig()
	require.NoError(t, config.isValid())

	// launch fake oauth OIDC server (http for simplicity)
	err := runTestWSTLSAuth(t, e2eWSTLSUpstreamOauthListener, "hod-test")
	require.NoError(t, err)

	// launch fake upstream resource server
	err = runTestWSTLSUpstream(t, e2eWSTLSUpstreamUpstreamListener, e2eWSTLSUpstreamUpstreamURL)
	require.NoError(t, err)

	// launch fake app server where to land after authentication
	err = runTestTLSApp(t, e2eWSTLSUpstreamAppListener, e2eWSTLSUpstreamAppURL)
	require.NoError(t, err)

	// launch keycloak-gatekeeper proxy
	err = runTestGatekeeper(t, config)
	require.NoError(t, err)

	// establish an authenticated session
	accessToken, cookies, err := runTestTLSConnect(t, config, e2eWSTLSUpstreamAppListener, e2eWSTLSUpstreamAppURL)
	require.NoErrorf(t, err, "could not login: %v", err)
	require.NotEmpty(t, accessToken)

	// scenario 1: establishing WS with upstream, w/ TLS (WSS)
	h := make(http.Header, 10)
	h.Set("Content-Type", "application/json")
	h.Add("Accept", "application/json")

	// test WSS upstream: looping echo web socket frames
	u, _ := url.Parse("wss://" + e2eWSTLSUpstreamProxyListener + "/echo")
	t.Logf("connecting to %s", u.String())

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Header: h,
	}
	copyCookies(req, cookies)

	wsDialer := *websocket.DefaultDialer
	wsDialer.TLSClientConfig = &tls.Config{
		RootCAs:    makeTestCACertPool(),
		NextProtos: []string{"http/1.1"}, // h2: not supported by gorilla/websocket
	}
	// nolint: bodyclose
	c, _, err := wsDialer.Dial(u.String(), req.Header)
	require.NoErrorf(t, err, "dial error: %v", err)
	defer c.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				_, isNetError := err.(*net.OpError)
				if isNetError || websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					t.Logf("client end of websocket pipe. OK")
				} else {
					t.Fail()
					t.Logf("client read error: %#v", err)
				}
				return
			}
			t.Logf("client received: %s", message)
		}
	}()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	// handle user interrupts
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		// run tests for a second
		time.Sleep(1 * time.Second)
		ticker.Stop()
		done <- struct{}{}
	}()

	for {
		select {
		case <-done:
			t.Log("done")
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			require.NoErrorf(t, err, "client write close error: %v", err)
			return
		case timestamp := <-ticker.C:
			err := c.WriteMessage(websocket.TextMessage, []byte(`{"message": "`+timestamp.String()+`"}`))
			require.NoErrorf(t, err, "client write error: %v", err)
		case <-interrupt:
			t.Log("user interrupt")
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			require.NoErrorf(t, err, "client write close error: %v", err)
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

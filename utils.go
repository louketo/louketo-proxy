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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gambol99/go-oidc/oidc"
	"github.com/golang/glog"
)

var (
	httpMethodRegex = regexp.MustCompile("^(ANY|GET|POST|DELETE|PATCH|HEAD|PUT|TRACE|CONNECT)$")
)

// encryptDataBlock encrypts the plaintext string with the key
func encryptDataBlock(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	cipherText := make([]byte, aes.BlockSize+len(plaintext))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plaintext)

	return cipherText, nil
}

// decryptDataBlock decrypts some cipher text
func decryptDataBlock(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(cipherText) < aes.BlockSize {
		return []byte{}, fmt.Errorf("failed to descrypt the ciphertext, the text is too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	return cipherText, nil
}

// initializeOpenID initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func initializeOpenID(discoveryURL, clientID, clientSecret, redirectURL string, scopes []string) (*oidc.Client, oidc.ClientConfig, error) {
	var err error
	var providerConfig oidc.ProviderConfig

	// step: attempt to retrieve the provider configuration
	gotConfig := false
	for i := 0; i < 3; i++ {
		glog.V(3).Infof("attempting to retreieve the openid configuration from the discovery url: %s", discoveryURL)
		providerConfig, err = oidc.FetchProviderConfig(http.DefaultClient, discoveryURL)
		if err == nil {
			gotConfig = true
			break
		}
		glog.V(3).Infof("failed to get provider configuration from discovery url: %s, %s", discoveryURL, err)

		time.Sleep(time.Second * 3)
	}
	if !gotConfig {
		return nil, oidc.ClientConfig{}, fmt.Errorf("failed to retrieve the provider configuration from discovery url")
	}

	// step: initialize the oidc configuration
	config := oidc.ClientConfig{
		ProviderConfig: providerConfig,
		Credentials: oidc.ClientCredentials{
			ID:     clientID,
			Secret: clientSecret,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback", redirectURL),
		Scope:       append(scopes, oidc.DefaultScope...),
	}

	glog.V(10).Infof("successfully retrieved the config from discovery url, %v", providerConfig)

	// step: attempt to create a new client
	client, err := oidc.NewClient(config)
	if err != nil {
		return nil, oidc.ClientConfig{}, err
	}

	// step: start the provider sync
	glog.V(10).Infof("starting the provider sync routine")
	//client.SyncProviderConfig(discoveryURL)

	return client, config, nil
}

func convertUnixTime(v string) (time.Time, error) {
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(i, 0), nil
}

// initializeReverseProxy create a reverse http proxy from the upstream
func initializeReverseProxy(upstream *url.URL) (*httputil.ReverseProxy, error) {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// step: we don't care about the cert verification here
	proxy.Transport = &http.Transport{
		//Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return proxy, nil
}

// tryDialEndpoint dials the upstream endpoint via plain
func tryDialEndpoint(location *url.URL) (net.Conn, error) {
	glog.V(10).Infof("attempting to dial: %s", location.String())
	// get the dial address
	dialAddr := dialAddress(location)

	switch location.Scheme {
	case "http":
		glog.V(10).Infof("connecting the http endpoint: %s", dialAddr)
		conn, err := net.Dial("tcp", dialAddr)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		glog.V(10).Infof("connecting to tls endpoint: %s", dialAddr)
		// step: construct and dial a tls endpoint
		conn, err := tls.Dial("tcp", dialAddr, &tls.Config{
			Rand:               rand.Reader,
			InsecureSkipVerify: true,
		})

		if err != nil {
			return nil, err
		}

		return conn, nil
	}
}

// isValidMethod ensure this is a valid http method type
func isValidMethod(method string) bool {
	return httpMethodRegex.MatchString(method)
}

// hasRoles checks the scopes are the same
func hasRoles(required, issued []string) bool {
	for _, role := range required {
		if !containedIn(role, issued) {
			return false
		}
	}

	return true
}

// containedIn checks if a value in a list of a strings
func containedIn(value string, list []string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}

	return false
}

// dialAddress extracts the dial address from the url
func dialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")
	if len(items) != 2 {
		switch location.Scheme {
		case "http":
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

// findCookie looks for a cookie in a list of cookies
func findCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

// isUpgradedConnection checks to see if the request is requesting
func isUpgradedConnection(req *http.Request) bool {
	if req.Header.Get(headerUpgrade) != "" {
		return true
	}

	return false
}

// transferBytes transfers bytes between the sink and source
func transferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	copied, err := io.Copy(dest, src)
	if err != nil {
		return copied, err
	}

	return copied, nil
}

// parserConfigFile reads and parses the configuration file
func parseConfigFile(filename string) (*Config, error) {
	config := new(Config)
	ext := filepath.Ext(filename)

	formatYAML := true
	switch ext {
	case "json":
		formatYAML = false
	}

	// step: read in the contents of the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// step: attempt to un-marshal the data
	switch formatYAML {
	case false:
		err = json.Unmarshal(content, config)
	default:
		err = yaml.Unmarshal(content, config)
	}

	if err != nil {
		return nil, err
	}

	return config, nil
}

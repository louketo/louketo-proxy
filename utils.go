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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gambol99/go-oidc/oidc"
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
		log.Infof("attempting to retreieve the openid configuration from the discovery url: %s", discoveryURL)
		providerConfig, err = oidc.FetchProviderConfig(http.DefaultClient, discoveryURL)
		if err == nil {
			gotConfig = true
			break
		}
		log.Infof("failed to get provider configuration from discovery url: %s, %s", discoveryURL, err)

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

	log.Infof("successfully retrieved the config from discovery url")

	// step: attempt to create a new client
	client, err := oidc.NewClient(config)
	if err != nil {
		return nil, oidc.ClientConfig{}, err
	}

	// step: start the provider sync
	client.SyncProviderConfig(discoveryURL)

	return client, config, nil
}

// convertUnixTime converts a unix timestamp to a Time
func convertUnixTime(v string) (time.Time, error) {
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(i, 0), nil
}

// decodeKeyPairs converts a list of strings (key=pair) to a map
func decodeKeyPairs(list []string) (map[string]string, error) {
	kp := make(map[string]string, 0)

	for _, x := range list {
		items := strings.Split(x, "=")
		if len(items) != 2 {
			return kp, fmt.Errorf("invalid tag '%s' should be key=pair", x)
		}
		kp[items[0]] = items[1]
	}

	return kp, nil
}

// initializeReverseProxy create a reverse http proxy from the upstream
func initializeReverseProxy(upstream *url.URL) (reverseProxy, error) {
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
	// get the dial address
	dialAddr := dialAddress(location)

	switch location.Scheme {
	case "http":
		conn, err := net.Dial("tcp", dialAddr)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
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

// decodeResource decodes the resource specification from the command line
func decodeResource(v string) (*Resource, error) {
	elements := strings.Split(v, "|")
	if len(elements) <= 0 {
		return nil, fmt.Errorf("the resource has no options")
	}

	resource := &Resource{}

	for _, x := range elements {
		// step: split up the keypair
		kp := strings.Split(x, "=")
		if len(kp) != 2 {
			return nil, fmt.Errorf("invalid resource keypair, should be (uri|roles|method|white-listed)=comma_values")
		}
		switch kp[0] {
		case "uri":
			resource.URL = kp[1]
		case "methods":
			resource.Methods = strings.Split(kp[1], ",")
		case "roles":
			resource.RolesAllowed = strings.Split(kp[1], ",")
		case "white-listed":
			value, err := strconv.ParseBool(kp[1])
			if err != nil {
				return nil, fmt.Errorf("the value of whitelisted must be true|TRUE|T or it's false equivilant")
			}
			resource.WhiteListed = value
		default:
			return nil, fmt.Errorf("invalid identifier, should be roles, uri or methods")
		}
	}

	return resource, nil
}

// validateResources checks and validates each of the resources
func validateResources(resources []*Resource) error {
	for _, x := range resources {
		if err := x.isValid(); err != nil {
			return err
		}
	}

	return nil
}

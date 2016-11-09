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
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gin-gonic/gin"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
)

var (
	httpMethodRegex = regexp.MustCompile("^(ANY|GET|POST|DELETE|PATCH|HEAD|PUT|TRACE)$")
	symbolsFilter   = regexp.MustCompilePOSIX("[_$><\\[\\].,\\+-/'%^&*()!\\\\]+")
)

//
// readConfigFile reads and parses the configuration file
//
func readConfigFile(filename string, config *Config) error {
	// step: read in the contents of the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, config)
	default:
		err = yaml.Unmarshal(content, config)
	}

	return err
}

//
// encryptDataBlock encrypts the plaintext string with the key
//
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

//
// decryptDataBlock decrypts some cipher text
//
func decryptDataBlock(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(cipherText) < aes.BlockSize {
		return []byte{}, errors.New("failed to descrypt the ciphertext, the text is too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	return cipherText, nil
}

//
// encodeText encodes the session state information into a value for a cookie to consume
//
func encodeText(plaintext string, key string) (string, error) {
	// step: encrypt the refresh state
	cipherText, err := encryptDataBlock([]byte(plaintext), []byte(key))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

//
// decodeText decodes the session state cookie value
//
func decodeText(state, key string) (string, error) {
	// step: decode the base64 encrypted cookie
	cipherText, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}

	// step: decrypt the cookie back in the expiration|token
	encoded, err := decryptDataBlock(cipherText, []byte(key))
	if err != nil {
		return "", ErrInvalidSession
	}

	return string(encoded), nil
}

// createOpenIDClient initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func createOpenIDClient(cfg *Config) (*oidc.Client, oidc.ProviderConfig, error) {
	var err error
	var providerConfig oidc.ProviderConfig

	// step: fix up the url if required, the underlining lib will add the .well-known/openid-configuration to the discovery url for us.
	if strings.HasSuffix(cfg.DiscoveryURL, "/.well-known/openid-configuration") {
		cfg.DiscoveryURL = strings.TrimSuffix(cfg.DiscoveryURL, "/.well-known/openid-configuration")
	}
	// initalize http client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipOpenIDProviderTLSVerify,
		},
	}
	providerHttpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 10,
	}

	// step: attempt to retrieve the provider configuration
	for i := 0; i < 3; i++ {
		log.Infof("attempting to retrieve the openid configuration from the discovery url: %s", cfg.DiscoveryURL)

		providerConfig, err = oidc.FetchProviderConfig(providerHttpClient, cfg.DiscoveryURL)
		if err == nil {
			goto GOT_CONFIG
		}
		log.Warnf("failed to get provider configuration from discovery url: %s, %s", cfg.DiscoveryURL, err)

		time.Sleep(time.Second * 3)
	}
	return nil, oidc.ProviderConfig{}, errors.New("failed to retrieve the provider configuration from discovery url")

GOT_CONFIG:
	client, err := oidc.NewClient(oidc.ClientConfig{
		ProviderConfig: providerConfig,
		Credentials: oidc.ClientCredentials{
			ID:     cfg.ClientID,
			Secret: cfg.ClientSecret,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback", cfg.RedirectionURL),
		Scope:       append(cfg.Scopes, oidc.DefaultScope...),
		HTTPClient:  providerHttpClient,
	})
	if err != nil {
		return nil, oidc.ProviderConfig{}, err
	}

	// step: start the provider sync
	client.SyncProviderConfig(cfg.DiscoveryURL)

	return client, providerConfig, nil
}

//
// decodeKeyPairs converts a list of strings (key=pair) to a map
//
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

//
// isValidHTTPMethod ensure this is a valid http method type
//
func isValidHTTPMethod(method string) bool {
	return httpMethodRegex.MatchString(method)
}

//
// cloneTLSConfig clones the tls configuration
//
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return &tls.Config{
		Rand:                     cfg.Rand,
		Time:                     cfg.Time,
		Certificates:             cfg.Certificates,
		NameToCertificate:        cfg.NameToCertificate,
		GetCertificate:           cfg.GetCertificate,
		RootCAs:                  cfg.RootCAs,
		NextProtos:               cfg.NextProtos,
		ServerName:               cfg.ServerName,
		ClientAuth:               cfg.ClientAuth,
		ClientCAs:                cfg.ClientCAs,
		InsecureSkipVerify:       cfg.InsecureSkipVerify,
		CipherSuites:             cfg.CipherSuites,
		PreferServerCipherSuites: cfg.PreferServerCipherSuites,
		SessionTicketsDisabled:   cfg.SessionTicketsDisabled,
		SessionTicketKey:         cfg.SessionTicketKey,
		ClientSessionCache:       cfg.ClientSessionCache,
		MinVersion:               cfg.MinVersion,
		MaxVersion:               cfg.MaxVersion,
		CurvePreferences:         cfg.CurvePreferences,
	}
}

//
// fileExists check if a file exists
//
func fileExists(filename string) bool {
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

//
// hasRoles checks the scopes are the same
//
func hasRoles(required, issued []string) bool {
	for _, role := range required {
		if !containedIn(role, issued) {
			return false
		}
	}

	return true
}

//
// containedIn checks if a value in a list of a strings
//
func containedIn(value string, list []string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}

	return false
}

//
// containsSubString checks if substring exists
//
func containsSubString(value string, list []string) bool {
	for _, x := range list {
		if strings.Contains(value, x) {
			return true
		}
	}

	return false
}

//
// tryDialEndpoint dials the upstream endpoint via plain
//
func tryDialEndpoint(location *url.URL) (net.Conn, error) {
	switch dialAddress := dialAddress(location); location.Scheme {
	case httpSchema:
		return net.Dial("tcp", dialAddress)
	default:
		return tls.Dial("tcp", dialAddress, &tls.Config{
			Rand:               rand.Reader,
			InsecureSkipVerify: true,
		})
	}
}

//
// isUpgradedConnection checks to see if the request is requesting
//
func isUpgradedConnection(req *http.Request) bool {
	if req.Header.Get(headerUpgrade) != "" {
		return true
	}

	return false
}

//
// transferBytes transfers bytes between the sink and source
//
func transferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	copied, err := io.Copy(dest, src)
	if err != nil {
		return copied, err
	}

	return copied, nil
}

//
// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
//
func tryUpdateConnection(cx *gin.Context, endpoint *url.URL) error {
	// step: dial the endpoint
	tlsConn, err := tryDialEndpoint(endpoint)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := cx.Writer.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer clientConn.Close()

	// step: write the request to upstream
	if err = cx.Request.Write(tlsConn); err != nil {
		return err
	}

	// step: copy the date between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go transferBytes(tlsConn, clientConn, &wg)
	go transferBytes(clientConn, tlsConn, &wg)
	wg.Wait()

	return nil
}

//
// dialAddress extracts the dial address from the url
//
func dialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")
	if len(items) != 2 {
		switch location.Scheme {
		case httpSchema:
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

//
// findCookie looks for a cookie in a list of cookies
//
func findCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

//
// toHeader is a helper method to play nice in the headers
//
func toHeader(v string) string {
	var list []string

	// step: filter out any symbols and convert to dashes
	for _, x := range symbolsFilter.Split(v, -1) {
		list = append(list, capitalize(x))
	}

	return strings.Join(list, "-")
}

//
// capitalize capitalizes the first letter of a word
//
func capitalize(s string) string {
	if s == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(s)

	return string(unicode.ToUpper(r)) + s[n:]
}

//
// mergeMaps simples copies the keys from source to destination
//
func mergeMaps(dest, source map[string]string) map[string]string {
	for k, v := range source {
		dest[k] = v
	}

	return dest
}

//
// loadCA loads the certificate authority
//
func loadCA(cert, key string) (*tls.Certificate, error) {
	caCert, err := ioutil.ReadFile(cert)
	if err != nil {
		return nil, err
	}

	caKey, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, err
	}

	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}

	ca.Leaf, err = x509.ParseCertificate(ca.Certificate[0])

	return &ca, err
}

//
// getWithin calculates a duration of x percent of the time period, i.e. something
// expires in 1 hours, get me a duration within 80%
//
func getWithin(expires time.Time, in float64) time.Duration {
	seconds := int(float64(expires.Sub(time.Now()).Seconds()) * in)
	return time.Duration(seconds) * time.Second
}

//
// getHashKey returns a hash of the encodes jwt token
//
func getHashKey(token *jose.JWT) string {
	hash := md5.Sum([]byte(token.Encode()))
	return hex.EncodeToString(hash[:])
}

//
// printError display the command line usage and error
//
func printError(message string, args ...interface{}) *cli.ExitError {
	return cli.NewExitError(fmt.Sprintf("[error] "+message, args...), 1)
}

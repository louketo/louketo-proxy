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

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

	"github.com/gambol99/keycloak-proxy/pkg/constants"
	"github.com/gambol99/keycloak-proxy/pkg/errors"

	"github.com/gambol99/go-oidc/jose"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
)

var (
	symbolsFilter = regexp.MustCompilePOSIX("[_$><\\[\\].,\\+-/'%^&*()!\\\\]+")
)

// ReadConfigFile reads and parses the configuration file
func ReadConfigFile(filename string, data interface{}) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, data)
	default:
		err = yaml.Unmarshal(content, data)
	}

	return err
}

// EncryptDataBlock encrypts the plaintext string with the key
func EncryptDataBlock(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptDataBlock decrypts some cipher text
func DecryptDataBlock(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.ErrDecryptionTextSmall
	}
	nonce, input := cipherText[:nonceSize], cipherText[nonceSize:]

	return gcm.Open(nil, nonce, input, nil)
}

// EncodeText encodes the session state information into a value for a cookie to consume
func EncodeText(plaintext string, key string) (string, error) {
	cipherText, err := EncryptDataBlock([]byte(plaintext), []byte(key))
	if err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(cipherText), nil
}

// DecodeText decodes the session state cookie value
func DecodeText(state, key string) (string, error) {
	cipherText, err := base64.RawStdEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}
	// step: decrypt the cookie back in the expiration|token
	encoded, err := DecryptDataBlock(cipherText, []byte(key))
	if err != nil {
		return "", errors.ErrInvalidSession
	}

	return string(encoded), nil
}

// DecodeKeyPairs converts a list of strings (key=pair) to a map
func DecodeKeyPairs(list []string) (map[string]string, error) {
	kp := make(map[string]string)

	for _, x := range list {
		items := strings.Split(x, "=")
		if len(items) != 2 {
			return kp, fmt.Errorf("invalid tag '%s' should be key=pair", x)
		}
		kp[items[0]] = items[1]
	}

	return kp, nil
}

// DefaultTo returns the value of the default
func DefaultTo(v, d string) string {
	if v != "" {
		return v
	}

	return d
}

// FileExists check if a file exists
func FileExists(filename string) bool {
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// HasRoles checks the scopes are the same
func HasRoles(required, issued []string) bool {
	for _, role := range required {
		if !ContainedIn(role, issued) {
			return false
		}
	}

	return true
}

// ContainedIn checks if a value in a list of a strings
func ContainedIn(value string, list []string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}

	return false
}

// ContainsSubString checks if substring exists
func ContainsSubString(value string, list []string) bool {
	for _, x := range list {
		if strings.Contains(value, x) {
			return true
		}
	}

	return false
}

// TryDialEndpoint dials the upstream endpoint via plain
func TryDialEndpoint(location *url.URL) (net.Conn, error) {
	switch dialAddress := DialAddress(location); location.Scheme {
	case constants.HTTPSchema:
		return net.Dial("tcp", dialAddress)
	default:
		return tls.Dial("tcp", dialAddress, &tls.Config{
			Rand:               rand.Reader,
			InsecureSkipVerify: true,
		})
	}
}

// IsUpgradedConnection checks to see if the request is requesting
func IsUpgradedConnection(req *http.Request) bool {
	return req.Header.Get(constants.HeaderUpgrade) != ""
}

// TransferBytes transfers bytes between the sink and source
func TransferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	return io.Copy(dest, src)
}

// TryUpdateConnection attempt to upgrade the connection to a http pdy stream
func TryUpdateConnection(req *http.Request, writer http.ResponseWriter, endpoint *url.URL) error {
	// step: dial the endpoint
	tlsConn, err := TryDialEndpoint(endpoint)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := writer.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer clientConn.Close()

	// step: write the request to upstream
	if err = req.Write(tlsConn); err != nil {
		return err
	}

	// step: copy the date between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go TransferBytes(tlsConn, clientConn, &wg)
	go TransferBytes(clientConn, tlsConn, &wg)
	wg.Wait()

	return nil
}

// DialAddress extracts the dial address from the url
func DialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")
	if len(items) != 2 {
		switch location.Scheme {
		case constants.HTTPSchema:
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

// FindCookie looks for a cookie in a list of cookies
func FindCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

// ToHeader is a helper method to play nice in the headers
func ToHeader(v string) string {
	var list []string

	// step: filter out any symbols and convert to dashes
	for _, x := range symbolsFilter.Split(v, -1) {
		list = append(list, Capitalize(x))
	}

	return strings.Join(list, "-")
}

// Capitalize capitalizes the first letter of a word
func Capitalize(s string) string {
	if s == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(s)

	return string(unicode.ToUpper(r)) + s[n:]
}

// MergeMaps simples copies the keys from source to destination
func MergeMaps(dest, source map[string]string) map[string]string {
	for k, v := range source {
		dest[k] = v
	}

	return dest
}

// LoadCA loads the certificate authority
func LoadCA(cert, key string) (*tls.Certificate, error) {
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

// GetWithin calculates a duration of x percent of the time period, i.e. something
// expires in 1 hours, get me a duration within 80%
func GetWithin(expires time.Time, within float64) time.Duration {
	left := expires.UTC().Sub(time.Now().UTC()).Seconds()
	if left <= 0 {
		return time.Duration(0)
	}
	seconds := int(left * within)

	return time.Duration(seconds) * time.Second
}

// GetHashKey returns a hash of the encodes jwt token
func GetHashKey(token *jose.JWT) string {
	hash := md5.Sum([]byte(token.Encode()))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// PrintError display the command line usage and error
func PrintError(message string, args ...interface{}) *cli.ExitError {
	return cli.NewExitError(fmt.Sprintf("[error] "+message, args...), 1)
}

// RealIP retrieves the client ip address from a http request
func RealIP(req *http.Request) string {
	ra := req.RemoteAddr
	if ip := req.Header.Get(constants.HeaderXForwardedFor); ip != "" {
		ra = strings.Split(ip, ", ")[0]
	} else if ip := req.Header.Get(constants.HeaderXRealIP); ip != "" {
		ra = ip
	} else {
		ra, _, _ = net.SplitHostPort(ra)
	}
	return ra
}

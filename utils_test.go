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
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeKeyPairs(t *testing.T) {
	testCases := []struct {
		List     []string
		KeyPairs map[string]string
		Ok       bool
	}{
		{
			List: []string{"a=b", "b=3"},
			KeyPairs: map[string]string{
				"a": "b",
				"b": "3",
			},
			Ok: true,
		},
		{
			List: []string{"add", "b=3"},
		},
	}

	for i, c := range testCases {
		kp, err := decodeKeyPairs(c.List)
		if err != nil && c.Ok {
			t.Errorf("test case %d should not have failed", i)
			continue
		}
		if !c.Ok {
			continue
		}
		if !reflect.DeepEqual(kp, c.KeyPairs) {
			t.Errorf("test case %d are not equal %v <-> %v", i, kp, c.KeyPairs)
		}
	}
}

func TestGetRequestHostURL(t *testing.T) {
	cs := []struct {
		Expected   string
		HostHeader string
		Hostname   string
		TLS        *tls.ConnectionState
	}{
		{
			Expected: "http://www.test.com",
			Hostname: "www.test.com",
		},
		{
			Expected: "http://",
		},
		{
			Expected:   "http://www.override.com",
			HostHeader: "www.override.com",
			Hostname:   "www.test.com",
		},
		{
			Expected: "https://www.test.com",
			Hostname: "www.test.com",
			TLS:      &tls.ConnectionState{},
		},
		{
			Expected:   "https://www.override.com",
			HostHeader: "www.override.com",
			Hostname:   "www.test.com",
			TLS:        &tls.ConnectionState{},
		},
	}
	for i, c := range cs {
		request := &http.Request{
			Method: http.MethodGet,
			Host:   c.Hostname,
			TLS:    c.TLS,
		}
		if c.HostHeader != "" {
			request.Header = make(http.Header)
			request.Header.Set("X-Forwarded-Host", c.HostHeader)
		}
		assert.Equal(t, c.Expected, getRequestHostURL(request), "case %d, expected: %s, got: %s", i, c.Expected, getRequestHostURL(request))
	}
}

func BenchmarkUUID(b *testing.B) {
	for n := 0; n < b.N; n++ {
		s, err := uuid.NewV1()
		if err != nil {
			b.Errorf("test case should not have failed")
		}
		_ = s.String()
	}
}

func TestDefaultTo(t *testing.T) {
	cs := []struct {
		Value    string
		Default  string
		Expected string
	}{
		{
			Value:    "",
			Default:  "hello",
			Expected: "hello",
		},
		{
			Value:    "world",
			Default:  "hello",
			Expected: "world",
		},
	}
	for _, c := range cs {
		assert.Equal(t, c.Expected, defaultTo(c.Value, c.Default))
	}
}

func TestEncryptDataBlock(t *testing.T) {
	testCase := []struct {
		Text string
		Key  string
		Ok   bool
	}{
		{
			Text: "hello world, my name is Louketo proxy",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTw",
			Ok:   true,
		},
		{
			Text: "hello world, my name is Louketo proxy",
			Key:  "DtNMS2eO7Fi5vsu",
		},
		{
			Text: "h",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTwtr",
		},
	}

	for i, test := range testCase {
		_, err := encryptDataBlock(bytes.NewBufferString(test.Text).Bytes(), bytes.NewBufferString(test.Key).Bytes())
		if err != nil && test.Ok {
			t.Errorf("test case: %d should not have failed, %s", i, err)
		}
	}
}

func TestEncodeText(t *testing.T) {
	session, err := encodeText("12245325632323263762", "1gjrlcjQ8RyKANngp9607txr5fF5fhf1")
	assert.NotEmpty(t, session)
	assert.NoError(t, err)
}

var (
	fakePlainText = []byte(`nFlhnhwRzC9uJ9mjhR0PQezUpIiDlU9ASLqH1KIKFhBZZrMZfnAAdHdgKs2OJoni8cTSQ
	JxkaNpboZ6hnrMytlw5kf0biF7dLTU885uHIGkUIRy75hx6BaTEEhbN36qVTxediEHd6xeBPS3qpJ7riO6J
	EeaQr1rroDL0LvmDyB6Zds4LdVQEmtUueusc7jkBz7gJ12vnTHIxviZM5rzcq4tyCbZO7Kb37RqZg5kbYGK
	PfErhUwUIin7jsNVE7coB`)
	fakeCipherText = []byte("lfQPTa6jwMTABaJhcrfVkoqcdyMVAettMsqgKXIALSKG5UpoYKbT/WgZjOiuCmEI0E/7piP8VATLOAHKDBNF2WrQOKSYF+gdHkh4NLv0cW0NZ2qyZeWhknywE6063ylhCYjJOrJA1z12i2bHHbjZZGfqkwfzyxxFLTv6jSbalpZ4oZcUcNY/DrtVk/K01qZw6o4l1f0FUL6UZVSirn+B3YDWLeVQ0FGr6jlhCpN203Rf688nqdBvhw4bUEQiykCMxWm2/rJBNWm2SzZgw65kb4W0ph1qjcoUjXBwNakK+E0Lw/fwi8+bUC1lkT8+hJpMLKZkzb07rbGAnmljQo0NkqJh4kl+aycsEhm9bZj+b6w0r795YugyNsyca5CnUvkB1Dg")
	fakeKey        = []byte("u3K0eKsmGl76jY1buzexwYoRRLLQrQck")
)

/*
func TestEncryptedText(t *testing.T) {
	s, err := encodeText(string(fakePlainText), string(fakeKey))
	require.NoError(t, err)
	require.NotEmpty(t, s)
	d, err := decodeText(s, string(fakeKey))
	require.NoError(t, err)
	require.NotEmpty(t, d)
	assert.Equal(t, string(fakePlainText), d)
	fmt.Printf("Encoded: '%s'\n", s)
	fmt.Printf("Decoded: '%s'\n", d)
}
*/

func BenchmarkEncryptDataBlock(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = encryptDataBlock(fakePlainText, fakeKey)
	}
}

func BenchmarkEncodeText(b *testing.B) {
	text := string(fakePlainText)
	key := string(fakeKey)
	for n := 0; n < b.N; n++ {
		_, _ = encodeText(text, key)
	}
}

func BenchmarkDecodeText(b *testing.B) {
	t := string(fakeCipherText)
	k := string(fakeKey)
	for n := 0; n < b.N; n++ {
		if _, err := decodeText(t, k); err != nil {
			b.FailNow()
		}
	}
}

func TestDecodeText(t *testing.T) {
	fakeKey := "HYLNt2JSzD7Lpz0djTRudmlOpbwx1oHB"
	fakeText := "12245325632323263762"

	encrypted, err := encodeText(fakeText, fakeKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decoded, _ := decodeText(encrypted, fakeKey)
	assert.NotNil(t, decoded, "the session should not have been nil")
	assert.Equal(t, decoded, fakeText, "the decoded text is not the same")
}

func TestFindCookie(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "cookie_there"},
	}
	assert.NotNil(t, findCookie("cookie_there", cookies))
	assert.Nil(t, findCookie("not_there", cookies))
}

func TestDecryptDataBlock(t *testing.T) {
	testCase := []struct {
		Text string
		Key  string
		Ok   bool
	}{
		{
			Text: "hello world, my name is Louketo proxy",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfss",
			Ok:   true,
		},
		{
			Text: "h",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTw",
			Ok:   true,
		},
	}

	for i, test := range testCase {
		cipher, err := encryptDataBlock(bytes.NewBufferString(test.Text).Bytes(), bytes.NewBufferString(test.Key).Bytes())
		if err != nil && test.Ok {
			t.Errorf("test case: %d should not have failed, %s", i, err)
		}

		plain, err := decryptDataBlock(cipher, bytes.NewBufferString(test.Key).Bytes())
		if err != nil {
			t.Errorf("test case: %d should not have failed, %s", i, err)
		}

		if string(plain) != test.Text {
			t.Errorf("test case: %d are not the same", i)
		}
	}
}

func TestHasAccessOK(t *testing.T) {
	cs := []struct {
		Have     []string
		Need     []string
		Required bool
	}{
		{},
		{
			Have: []string{"a", "b"},
		},
		{
			Have:     []string{"a", "b", "c"},
			Need:     []string{"a", "b"},
			Required: true,
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"a", "c"},
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"c"},
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"b"},
		},
		{
			Have: []string{"a", "b", "c"},
			Need: []string{"b"},
		},
		{
			Have: []string{"a", "b"},
			Need: []string{"a"},
		},
		{
			Have:     []string{"a", "b"},
			Need:     []string{"a"},
			Required: true,
		},
		{
			Have:     []string{"b", "a"},
			Need:     []string{"a"},
			Required: true,
		},
	}
	for i, x := range cs {
		assert.True(t, hasAccess(x.Need, x.Have, x.Required), "case: %d should be true, have: %v, need: %v, require: %t ", i, x.Have, x.Need, x.Required)
	}
}

func TestHasAccessBad(t *testing.T) {
	cs := []struct {
		Have     []string
		Need     []string
		Required bool
	}{
		{
			Have: []string{"a", "b"},
			Need: []string{"c"},
		},
		{
			Have:     []string{"a", "b"},
			Need:     []string{"c"},
			Required: true,
		},
		{
			Have:     []string{"a", "c"},
			Need:     []string{"a", "b"},
			Required: true,
		},
		{
			Have:     []string{"a", "b", "c"},
			Need:     []string{"b", "j"},
			Required: true,
		},
		{
			Have:     []string{"a", "b", "c"},
			Need:     []string{"a", "d"},
			Required: true,
		},
	}

	for i, x := range cs {
		assert.False(t, hasAccess(x.Need, x.Have, x.Required), "case: %d should be false, have: %v, need: %v, require: %t ", i, x.Have, x.Need, x.Required)
	}
}

func TestContainedIn(t *testing.T) {
	assert.False(t, containedIn("1", []string{"2", "3", "4"}))
	assert.True(t, containedIn("1", []string{"1", "2", "3", "4"}))
}

func TestContainsSubString(t *testing.T) {
	assert.False(t, containsSubString("bar.com", []string{"foo.bar.com"}))
	assert.True(t, containsSubString("www.foo.bar.com", []string{"foo.bar.com"}))
	assert.True(t, containsSubString("foo.bar.com", []string{"bar.com"}))
	assert.True(t, containsSubString("star.domain.com", []string{"domain.com", "domain1.com"}))
	assert.True(t, containsSubString("star.domain1.com", []string{"domain.com", "domain1.com"}))
	assert.True(t, containsSubString("test.test.svc.cluster.local", []string{"svc.cluster.local"}))

	assert.False(t, containsSubString("star.domain1.com", []string{"domain.com", "sub.domain1.com"}))
	assert.False(t, containsSubString("svc.cluster.local", []string{"nginx.pr1.svc.cluster.local"}))
	assert.False(t, containsSubString("cluster.local", []string{"nginx.pr1.svc.cluster.local"}))
	assert.False(t, containsSubString("pr1", []string{"nginx.pr1.svc.cluster.local"}))
}

func BenchmarkContainsSubString(t *testing.B) {
	for n := 0; n < t.N; n++ {
		containsSubString("svc.cluster.local", []string{"nginx.pr1.svc.cluster.local"})
	}
}

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

func TestIdValidHTTPMethod(t *testing.T) {
	cs := []struct {
		Method string
		Ok     bool
	}{
		{Method: "GET", Ok: true},
		{Method: "GETT"},
		{Method: "CONNECT", Ok: false},
		{Method: "PUT", Ok: true},
		{Method: "PATCH", Ok: true},
	}
	for _, x := range cs {
		assert.Equal(t, x.Ok, isValidHTTPMethod(x.Method))
	}
}

func TestFileExists(t *testing.T) {
	if fileExists("no_such_file_exsit_32323232") {
		t.Error("we should have received false")
	}
	tmpfile, err := ioutil.TempFile("/tmp", fmt.Sprintf("test_file_%d", os.Getpid()))
	if err != nil {
		t.Fatalf("failed to create the temporary file, %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if !fileExists(tmpfile.Name()) {
		t.Error("we should have received a true")
	}
}

func TestGetWithin(t *testing.T) {
	cs := []struct {
		Expires  time.Time
		Percent  float64
		Expected time.Duration
	}{
		{
			Expires:  time.Now().Add(time.Duration(1) * time.Hour),
			Percent:  0.10,
			Expected: 359000000000,
		},
		{
			Expires:  time.Now().Add(time.Duration(1) * time.Hour),
			Percent:  0.20,
			Expected: 719000000000,
		},
	}
	for _, x := range cs {
		assert.InDelta(t, x.Expected, getWithin(x.Expires, x.Percent), 1000000001)
	}
}

func TestToHeader(t *testing.T) {
	cases := []struct {
		Word     string
		Expected string
	}{
		{
			Word:     "given_name",
			Expected: "Given-Name",
		},
		{
			Word:     "family%name",
			Expected: "Family-Name",
		},
		{
			Word:     "perferredname",
			Expected: "Perferredname",
		},
	}
	for i, x := range cases {
		assert.Equal(t, x.Expected, toHeader(x.Word), "case %d, expected: %s but got: %s",
			i, x.Expected, toHeader(x.Word))
	}
}

func TestCapitalize(t *testing.T) {
	cases := []struct {
		Word     string
		Expected string
	}{
		{
			Word:     "given",
			Expected: "Given",
		},
		{
			Word:     "1iven",
			Expected: "1iven",
		},
		{
			Word:     "Test this",
			Expected: "Test this",
		},
	}
	for i, x := range cases {
		assert.Equal(t, x.Expected, capitalize(x.Word), "case %d, expected: %s but got: %s", i, x.Expected,
			capitalize(x.Word))
	}
}

func TestMergeMaps(t *testing.T) {
	cases := []struct {
		Source   map[string]string
		Dest     map[string]string
		Expected map[string]string
	}{
		{
			Source: map[string]string{
				"a": "b",
				"b": "b",
			},
			Dest: map[string]string{
				"c": "c",
			},
			Expected: map[string]string{
				"a": "b",
				"b": "b",
				"c": "c",
			},
		},
	}
	for i, x := range cases {
		merged := mergeMaps(x.Dest, x.Source)
		if !reflect.DeepEqual(x.Expected, merged) {
			t.Errorf("case %d, expected: %v but got: %v", i, x.Expected, merged)
		}
	}
}

func TestReadConfiguration(t *testing.T) {
	testCases := []struct {
		Content string
		Ok      bool
	}{
		{
			Content: `
discovery_url: https://keyclock.domain.com/
client-id: <client_id>
secret: <secret>
`,
		},
		{
			Content: `
discovery_url: https://keyclock.domain.com
client-id: <client_id>
secret: <secret>
upstream-url: http://127.0.0.1:8080
redirection_url: http://127.0.0.1:3000
`,
			Ok: true,
		},
	}

	for i, test := range testCases {
		// step: write the fake config file
		file := writeFakeConfigFile(t, test.Content)

		config := new(Config)
		err := readConfigFile(file.Name(), config)
		if test.Ok && err != nil {
			os.Remove(file.Name())
			t.Errorf("test case %d should not have failed, config: %v, error: %s", i, config, err)
		}
		os.Remove(file.Name())
	}
}

func getFakeURL(location string) *url.URL {
	u, _ := url.Parse(location)
	return u
}

func writeFakeConfigFile(t *testing.T, content string) *os.File {
	f, err := ioutil.TempFile("", "node_label_file")
	if err != nil {
		t.Fatalf("unexpected error creating node_label_file: %v", err)
	}
	f.Close()

	if err := ioutil.WriteFile(f.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return f
}

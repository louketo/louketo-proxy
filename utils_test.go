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

	"github.com/stretchr/testify/assert"
)

func TestNewOpenIDClient(t *testing.T) {
	_, auth, _ := newTestProxyService(nil)
	client, _, _, err := newOpenIDClient(&Config{
		DiscoveryURL: auth.location.String() + "/auth/realms/hod-test",
	})
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

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
			Text: "hello world, my name is keycloak proxy",
			Key:  "DtNMS2eO7Fi5vsuLrW55nrRbir2kPfTw",
			Ok:   true,
		},
		{
			Text: "hello world, my name is keycloak proxy",
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

func TestDecodeText(t *testing.T) {
	fakeKey := "HYLNt2JSzD7Lpz0djTRudmlOpbwx1oHB"
	fakeText := "12245325632323263762"

	encrypted, err := encodeText(fakeText, fakeKey)
	if !assert.NoError(t, err) {
		t.Error("the encryptStateSession() should not have handed an error")
		t.FailNow()
	}
	assert.NotEmpty(t, encrypted)

	decoded, _ := decodeText(encrypted, fakeKey)
	assert.NotNil(t, decoded, "the session should not have been nil")
	assert.Equal(t, decoded, fakeText, "the decoded text is not the same")
}

func TestFindCookie(t *testing.T) {
	cookies := []*http.Cookie{
		{
			Name: "cookie_there",
		},
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
			Text: "hello world, my name is keycloak proxy",
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

func TestHasRoles(t *testing.T) {
	testCases := []struct {
		Roles    []string
		Required []string
		Ok       bool
	}{
		{
			Roles:    []string{"a", "b", "c"},
			Required: []string{"a", "b"},
			Ok:       true,
		},
		{
			Roles:    []string{"a", "b"},
			Required: []string{"a", "b"},
			Ok:       true,
		},
		{
			Roles:    []string{"a", "b", "c"},
			Required: []string{"a", "d"},
		},
	}

	for i, test := range testCases {
		if !hasRoles(test.Required, test.Roles) && test.Ok {
			assert.Fail(t, "test case: %i should have ok, %s, %s", i, test.Roles, test.Required)
		}
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

func TestCloneTLSConfig(t *testing.T) {
	assert.NotNil(t, cloneTLSConfig(nil))
	assert.NotNil(t, cloneTLSConfig(&tls.Config{}))
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
		assert.Equal(t, x.Expected, getWithin(x.Expires, x.Percent))
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

	if err := ioutil.WriteFile(f.Name(), []byte(content), 0700); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return f
}

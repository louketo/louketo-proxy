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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gambol99/keycloak-proxy/pkg/constants"

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
		kp, err := DecodeKeyPairs(c.List)
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
		assert.Equal(t, c.Expected, DefaultTo(c.Value, c.Default))
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
		_, err := EncryptDataBlock(bytes.NewBufferString(test.Text).Bytes(), bytes.NewBufferString(test.Key).Bytes())
		if err != nil && test.Ok {
			t.Errorf("test case: %d should not have failed, %s", i, err)
		}
	}
}

func TestEncodeText(t *testing.T) {
	session, err := EncodeText("12245325632323263762", "1gjrlcjQ8RyKANngp9607txr5fF5fhf1")
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
		EncryptDataBlock(fakePlainText, fakeKey)
	}
}

func BenchmarkEncodeText(b *testing.B) {
	text := string(fakePlainText)
	key := string(fakeKey)
	for n := 0; n < b.N; n++ {
		EncodeText(text, key)
	}
}

func BenchmarkDecodeText(b *testing.B) {
	t := string(fakeCipherText)
	k := string(fakeKey)
	for n := 0; n < b.N; n++ {
		if _, err := DecodeText(t, k); err != nil {
			b.FailNow()
		}
	}
}

func TestDecodeText(t *testing.T) {
	fakeKey := "HYLNt2JSzD7Lpz0djTRudmlOpbwx1oHB"
	fakeText := "12245325632323263762"

	encrypted, err := EncodeText(fakeText, fakeKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decoded, _ := DecodeText(encrypted, fakeKey)
	assert.NotNil(t, decoded, "the session should not have been nil")
	assert.Equal(t, decoded, fakeText, "the decoded text is not the same")
}

func TestFindCookie(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "cookie_there"},
	}
	assert.NotNil(t, FindCookie("cookie_there", cookies))
	assert.Nil(t, FindCookie("not_there", cookies))
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
		cipher, err := EncryptDataBlock(bytes.NewBufferString(test.Text).Bytes(), bytes.NewBufferString(test.Key).Bytes())
		if err != nil && test.Ok {
			t.Errorf("test case: %d should not have failed, %s", i, err)
		}

		plain, err := DecryptDataBlock(cipher, bytes.NewBufferString(test.Key).Bytes())
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
		if !HasRoles(test.Required, test.Roles) && test.Ok {
			assert.Fail(t, "test case: %i should have ok, %s, %s", i, test.Roles, test.Required)
		}
	}
}

func TestContainedIn(t *testing.T) {
	assert.False(t, ContainedIn("1", []string{"2", "3", "4"}))
	assert.True(t, ContainedIn("1", []string{"1", "2", "3", "4"}))
}

func TestContainsSubString(t *testing.T) {
	assert.False(t, ContainsSubString("bar.com", []string{"foo.bar.com"}))
	assert.True(t, ContainsSubString("www.foo.bar.com", []string{"foo.bar.com"}))
	assert.True(t, ContainsSubString("foo.bar.com", []string{"bar.com"}))
	assert.True(t, ContainsSubString("star.domain.com", []string{"domain.com", "domain1.com"}))
	assert.True(t, ContainsSubString("star.domain1.com", []string{"domain.com", "domain1.com"}))
	assert.True(t, ContainsSubString("test.test.svc.cluster.local", []string{"svc.cluster.local"}))

	assert.False(t, ContainsSubString("star.domain1.com", []string{"domain.com", "sub.domain1.com"}))
	assert.False(t, ContainsSubString("svc.cluster.local", []string{"nginx.pr1.svc.cluster.local"}))
	assert.False(t, ContainsSubString("cluster.local", []string{"nginx.pr1.svc.cluster.local"}))
	assert.False(t, ContainsSubString("pr1", []string{"nginx.pr1.svc.cluster.local"}))
}

func BenchmarkContainsSubString(t *testing.B) {
	for n := 0; n < t.N; n++ {
		ContainsSubString("svc.cluster.local", []string{"nginx.pr1.svc.cluster.local"})
	}
}

func TestDialAddress(t *testing.T) {
	assert.Equal(t, DialAddress(getFakeURL("http://127.0.0.1")), "127.0.0.1:80")
	assert.Equal(t, DialAddress(getFakeURL("https://127.0.0.1")), "127.0.0.1:443")
	assert.Equal(t, DialAddress(getFakeURL("http://127.0.0.1:8080")), "127.0.0.1:8080")
}

func TestIsUpgradedConnection(t *testing.T) {
	header := http.Header{}
	header.Add(constants.HeaderUpgrade, "")
	assert.False(t, IsUpgradedConnection(&http.Request{Header: header}))
	header.Set(constants.HeaderUpgrade, "set")
	assert.True(t, IsUpgradedConnection(&http.Request{Header: header}))
}

func TestFileExists(t *testing.T) {
	if FileExists("no_such_file_exsit_32323232") {
		t.Error("we should have received false")
	}
	tmpfile, err := ioutil.TempFile("/tmp", fmt.Sprintf("test_file_%d", os.Getpid()))
	if err != nil {
		t.Fatalf("failed to create the temporary file, %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if !FileExists(tmpfile.Name()) {
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
		assert.Equal(t, x.Expected, GetWithin(x.Expires, x.Percent))
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
		assert.Equal(t, x.Expected, ToHeader(x.Word), "case %d, expected: %s but got: %s",
			i, x.Expected, ToHeader(x.Word))
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
		assert.Equal(t, x.Expected, Capitalize(x.Word), "case %d, expected: %s but got: %s", i, x.Expected,
			Capitalize(x.Word))
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
		merged := MergeMaps(x.Dest, x.Source)
		if !reflect.DeepEqual(x.Expected, merged) {
			t.Errorf("case %d, expected: %v but got: %v", i, x.Expected, merged)
		}
	}
}

func TestReadConfiguration(t *testing.T) {
	var test struct {
		ID   int    `yaml:"id"`
		Name string `yaml:"name"`
	}
	assert.Error(t, ReadConfigFile("not_found", nil))
	content := `
id: 12
name: test
`
	file := writeFakeConfigFile(t, content)
	assert.NoError(t, ReadConfigFile(file.Name(), &test))
	assert.Equal(t, 12, test.ID)
	assert.Equal(t, "test", test.Name)
	os.Remove(file.Name())
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

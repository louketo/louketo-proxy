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
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestValidateResources(t *testing.T) {
	testCases := []struct {
		Resources []*Resource
		Ok        bool
	}{
		{
			Resources: []*Resource{
				{
					URL: "/test",
				},
				{
					URL:     "/test1",
					Methods: []string{},
				},
			},
			Ok: true,
		},
		{
			Resources: []*Resource{
				{
					URL: "/test",
				},
				{},
			},
		},
	}

	for i, c := range testCases {
		err := validateResources(c.Resources)
		if err != nil && c.Ok {
			t.Errorf("case %d should not have failed", i)
			continue
		}
	}
}

func TestDecodeResource(t *testing.T) {
	testCases := []struct {
		Option   string
		Ok       bool
		Resource *Resource
	}{
		{
			Option: "uri=/admin",
			Ok:     true,
			Resource: &Resource{
				URL: "/admin",
			},
		},
		{
			Option: "uri=/admin/sso|roles=test,test1",
			Ok:     true,
			Resource: &Resource{
				URL:   "/admin/sso",
				Roles: []string{"test", "test1"},
			},
		},
		{
			Option: "uri=/admin/sso|roles=test,test1|methods=GET,POST",
			Ok:     true,
			Resource: &Resource{
				URL:     "/admin/sso",
				Roles:   []string{"test", "test1"},
				Methods: []string{"GET", "POST"},
			},
		},
		{
			Option: "uri=/allow_me|white-listed=true",
			Ok:     true,
			Resource: &Resource{
				URL:         "/allow_me",
				WhiteListed: true,
			},
		},
		{
			Option: "",
		},
	}

	for i, c := range testCases {
		rc, err := decodeResource(c.Option)
		if c.Ok && err != nil {
			t.Errorf("test case %d should not have failed, error: %s", i, err)
			continue
		}
		if !reflect.DeepEqual(c.Resource, rc) {
			t.Errorf("test case %d are not equal %v - %v", i, c.Resource, rc)
		}
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

func getFakeURL(location string) *url.URL {
	u, _ := url.Parse(location)
	return u
}

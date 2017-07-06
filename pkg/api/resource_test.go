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

package api

import (
	"testing"

	"github.com/gambol99/keycloak-proxy/pkg/constants"

	"github.com/stretchr/testify/assert"
)

func TestDecodeResourceBad(t *testing.T) {
	cs := []struct {
		Option   string
		Resource *Resource
	}{
		{Option: "unknown=bad"},
		{Option: "uri=/|unknown=bad"},
		{Option: "uri"},
		{Option: "uri=hello"},
		{Option: "uri=/|white-listed=ERROR"},
	}
	for i, c := range cs {
		if _, err := NewResource().Parse(c.Option); err == nil {
			t.Errorf("case %d should have errored", i)
		}
	}
}

func TestResourceParseOk(t *testing.T) {
	cs := []struct {
		Option   string
		Resource *Resource
	}{
		{
			Option:   "uri=/admin",
			Resource: &Resource{URI: "/admin", Methods: constants.AllHTTPMethods},
		},
		{
			Option:   "uri=/",
			Resource: &Resource{URI: "/", Methods: constants.AllHTTPMethods},
		},
		{
			Option:   "uri=/admin/sso|roles=test,test1",
			Resource: &Resource{URI: "/admin/sso", Roles: []string{"test", "test1"}, Methods: constants.AllHTTPMethods},
		},
		{
			Option:   "uri=/admin/sso|roles=test,test1|methods=GET,POST",
			Resource: &Resource{URI: "/admin/sso", Roles: []string{"test", "test1"}, Methods: []string{"GET", "POST"}},
		},
		{
			Option:   "uri=/allow_me|white-listed=true",
			Resource: &Resource{URI: "/allow_me", WhiteListed: true, Methods: constants.AllHTTPMethods},
		},
		{
			Option:   "uri=/*|methods=any",
			Resource: &Resource{URI: "/*", Methods: constants.AllHTTPMethods},
		},
		{
			Option:   "uri=/*|methods=any",
			Resource: &Resource{URI: "/*", Methods: constants.AllHTTPMethods},
		},
	}
	for i, x := range cs {
		r, err := NewResource().Parse(x.Option)
		assert.NoError(t, err, "case %d should not have errored with: %s", i, err)
		assert.Equal(t, r, x.Resource, "case %d, expected: %#v, got: %#v", i, x.Resource, r)
	}
}

func TestIsValid(t *testing.T) {
	testCases := []struct {
		Resource *Resource
		Ok       bool
	}{
		{
			Resource: &Resource{URI: "/test"}, Ok: true,
		},
		{
			Resource: &Resource{URI: "/test", Methods: []string{"GET"}}, Ok: true,
		},
		{
			Resource: &Resource{},
		},
		{
			Resource: &Resource{URI: "/oauth"},
		},
		{
			Resource: &Resource{URI: "/test", Methods: []string{"NO_SUCH_METHOD"}},
		},
	}

	for i, c := range testCases {
		if err := c.Resource.IsValid(); err != nil && c.Ok {
			t.Errorf("case %d should not have failed, error: %s", i, err)
		}
	}
}

func TestIsValidHTTPMethod(t *testing.T) {
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

func TestResourceString(t *testing.T) {
	resource := &Resource{
		Roles: []string{"1", "2", "3"},
	}
	if s := resource.String(); s == "" {
		t.Error("we should have received a string")
	}
}

func TestGetRoles(t *testing.T) {
	resource := &Resource{
		Roles: []string{"1", "2", "3"},
	}

	if resource.GetRoles() != "1,2,3" {
		t.Error("the resource roles not as expected")
	}
}

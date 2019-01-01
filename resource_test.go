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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeResourceBad(t *testing.T) {
	cs := []struct {
		Option string
	}{
		{Option: "unknown=bad"},
		{Option: "uri=/|unknown=bad"},
		{Option: "uri"},
		{Option: "uri=hello"},
		{Option: "uri=/|white-listed=ERROR"},
		{Option: "uri=/|require-any-role=BAD"},
	}
	for i, c := range cs {
		if _, err := newResource().parse(c.Option); err == nil {
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
			Resource: &Resource{URL: "/admin", Methods: allHTTPMethods},
		},
		{
			Option:   "uri=/",
			Resource: &Resource{URL: "/", Methods: allHTTPMethods},
		},
		{
			Option:   "uri=/admin/sso|roles=test,test1",
			Resource: &Resource{URL: "/admin/sso", Roles: []string{"test", "test1"}, Methods: allHTTPMethods},
		},
		{
			Option:   "uri=/admin/sso|roles=test,test1|methods=GET,POST",
			Resource: &Resource{URL: "/admin/sso", Roles: []string{"test", "test1"}, Methods: []string{"GET", "POST"}},
		},
		{
			Option:   "uri=/allow_me|white-listed=true",
			Resource: &Resource{URL: "/allow_me", WhiteListed: true, Methods: allHTTPMethods},
		},
		{
			Option:   "uri=/*|methods=any",
			Resource: &Resource{URL: "/*", Methods: allHTTPMethods},
		},
		{
			Option:   "uri=/*|methods=any",
			Resource: &Resource{URL: "/*", Methods: allHTTPMethods},
		},
		{
			Option:   "uri=/*|groups=admin,test",
			Resource: &Resource{URL: "/*", Methods: allHTTPMethods, Groups: []string{"admin", "test"}},
		},
		{
			Option:   "uri=/*|groups=admin",
			Resource: &Resource{URL: "/*", Methods: allHTTPMethods, Groups: []string{"admin"}},
		},
		{
			Option:   "uri=/*|require-any-role=true",
			Resource: &Resource{URL: "/*", Methods: allHTTPMethods, RequireAnyRole: true},
		},
	}
	for i, x := range cs {
		r, err := newResource().parse(x.Option)
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
			Resource: &Resource{URL: "/test"},
			Ok:       true,
		},
		{
			Resource: &Resource{URL: "/test", Methods: []string{"GET"}},
			Ok:       true,
		},
		{
			Resource: &Resource{URL: "/", Methods: allHTTPMethods},
		},
		{
			Resource: &Resource{URL: "/admin/", Methods: allHTTPMethods},
		},
		{
			Resource: &Resource{},
		},
		{
			Resource: &Resource{URL: "/oauth"},
		},
		{
			Resource: &Resource{
				URL:     "/test",
				Methods: []string{"NO_SUCH_METHOD"},
			},
		},
	}

	for i, c := range testCases {
		err := c.Resource.valid()
		if err != nil && c.Ok {
			t.Errorf("case %d should not have failed, error: %s", i, err)
		}
	}
}

var expectedRoles = []string{"1", "2", "3"}

const rolesList = "1,2,3"

func TestResourceString(t *testing.T) {
	resource := &Resource{
		Roles: expectedRoles,
	}
	if s := resource.String(); s == "" {
		t.Error("we should have received a string")
	}
}

func TestGetRoles(t *testing.T) {
	resource := &Resource{
		Roles: expectedRoles,
	}

	if resource.getRoles() != rolesList {
		t.Error("the resource roles not as expected")
	}
}

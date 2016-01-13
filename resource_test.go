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
)

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
			Resource: &Resource{},
		},
		{
			Resource: &Resource{
				URL:     "/test",
				Methods: []string{"NO_SUCH_METHOD"},
			},
		},
	}

	for i, c := range testCases {
		err := c.Resource.isValid()
		if err != nil && c.Ok {
			t.Errorf("case %d should not have failed", i)
		}
	}
}

func TestGetRoles(t *testing.T) {
	resource := &Resource{
		RolesAllowed: []string{"1", "2", "3"},
	}

	if resource.getRoles() != "1,2,3" {
		t.Error("the resource roles not as expected")
	}
}

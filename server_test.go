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

func newFakeKeycloakProxy(t *testing.T) *KeycloakProxy {
	return &KeycloakProxy{
		config: &Config{
			DiscoveryURL:   "127.0.0.1:",
			ClientID:       "test_client",
			Secret:         "test_secret",
			EncryptionKey:  "AgXa7xRcoClDEU0ZDSH4X0XhL5Qy2Z2j",
			Scopes:         []string{},
			RefreshSession: false,
			Resources: []*Resource{
				&Resource{
					URL:          "/protect",
					Methods:      []string{"GET"},
					RolesAllowed: []string{"test_role"},
				},
			},
		},
	}
}

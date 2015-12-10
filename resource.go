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
	"fmt"
	"strings"
)

func (r Resource) String() string {
	var requiredRoles string
	var requireMethods string

	switch len(r.RolesAllowed) {
	case 0:
		requiredRoles = "authentication"
	default:
		requiredRoles = strings.Join(r.RolesAllowed, ",")
	}

	switch len(r.Methods) {
	case 0:
		requireMethods = "ANY"
	default:
		requireMethods = strings.Join(r.Methods, ",")
	}

	return fmt.Sprintf("uri: %s, methods: [%s], required: [%s]", r.URL, requireMethods, requiredRoles)
}

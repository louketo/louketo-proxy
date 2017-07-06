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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gambol99/keycloak-proxy/pkg/constants"
)

// NewResource returns a new resource
func NewResource() *Resource {
	return &Resource{
		Methods: constants.AllHTTPMethods,
	}
}

// Parse decodes a resource definition
func (r *Resource) Parse(resource string) (*Resource, error) {
	if resource == "" {
		return nil, errors.New("the resource has no options")
	}
	for _, x := range strings.Split(resource, "|") {
		items := strings.Split(x, "=")
		if len(items) != 2 {
			return nil, errors.New("invalid resource keypair, should be (uri|roles|methods|white-listed)=comma_values")
		}

		switch items[0] {
		case "uri":
			r.URI = items[1]
			if !strings.HasPrefix(r.URI, "/") {
				return nil, errors.New("the resource uri should start with a '/'")
			}
		case "methods":
			r.Methods = strings.Split(items[1], ",")
			if len(r.Methods) == 1 {
				if r.Methods[0] == "any" || r.Methods[0] == "ANY" {
					r.Methods = constants.AllHTTPMethods
				}
			}
		case "roles":
			r.Roles = strings.Split(items[1], ",")
		case "white-listed":
			value, err := strconv.ParseBool(items[1])
			if err != nil {
				return nil, errors.New("the value of whitelisted must be true|TRUE|T or it's false equivalent")
			}
			r.WhiteListed = value
		default:
			return nil, errors.New("invalid identifier, should be roles, uri or methods")
		}
	}

	return r, nil
}

// IsValid ensure the resource is valid
func (r *Resource) IsValid() error {
	if strings.HasPrefix(r.URI, constants.OauthURL) {
		return errors.New("this is used by the oauth handlers")
	}
	if r.Methods == nil {
		r.Methods = make([]string, 0)
	}
	if r.Roles == nil {
		r.Roles = make([]string, 0)
	}
	if r.URI == "" {
		return errors.New("neither uri or hostname specified")
	}
	// step: add any of no methods
	if len(r.Methods) <= 0 {
		r.Methods = constants.AllHTTPMethods
	}

	return nil
}

// GetRoles returns a list of roles for this resource
func (r Resource) GetRoles() string {
	return strings.Join(r.Roles, ",")
}

// String returns a string representation of the resource
func (r Resource) String() string {
	if r.WhiteListed {
		return fmt.Sprintf("uri: %s, white-listed", r.URI)
	}

	roles := "auth only"
	methods := "ANY"

	if len(r.Roles) > 0 {
		roles = strings.Join(r.Roles, ",")
	}
	if len(r.Methods) > 0 {
		methods = strings.Join(r.Methods, ",")
	}

	return fmt.Sprintf("uri: %s, methods: %s, required: %s", r.URI, methods, roles)
}

// isValidHTTPMethod ensure this is a valid http method type
func isValidHTTPMethod(method string) bool {
	for _, x := range constants.AllHTTPMethods {
		if method == x {
			return true
		}
	}

	return false
}

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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Resource represents an upstream resource to protect
type Resource struct {
	// URL the url for the resource
	URL string `json:"uri" yaml:"uri"`
	// Several URLs sharing the same config: expanded as as many resources
	URLs []string `json:"uris" yaml:"uris"`
	// Methods the method type
	Methods []string `json:"methods" yaml:"methods"`
	// WhiteListed permits the prefix through
	WhiteListed bool `json:"white-listed" yaml:"white-listed"`
	// BlackListed denies the prefix through
	BlackListed bool `json:"black-listed" yaml:"black-listed"`
	// RequireAnyRole indicates that ANY of the roles are required, the default is all
	RequireAnyRole bool `json:"require-any-role" yaml:"require-any-role"`
	// Roles the roles required to access this url
	Roles []string `json:"roles" yaml:"roles"`
	// Groups is a list of groups the user is in
	Groups []string `json:"groups" yaml:"groups"`
	// EnableCSRF enables CSRF check on this upstream Resource
	EnableCSRF bool `json:"enable-csrf" yaml:"enable-csrf"`
	// StripBasePath is the prefix to strip from URL before sending upstream
	StripBasePath string `json:"strip-basepath" yaml:"strip-basepath"`
	// Upstream is the upstream endpoint i.e whom were proxying to
	Upstream string `json:"upstream-url" yaml:"upstream-url" usage:"url for the upstream endpoint you wish to proxy this resource"`
	// TODO: UpstreamCA is the path to a CA certificate in PEM format to validate the upstream certificate
	//UpstreamCA string `json:"upstream-ca" yaml:"upstream-ca" usage:"the path to a file container a CA certificate to validate the upstream tls endpoint for this resource"`
}

func newResource() *Resource {
	return &Resource{
		Methods: allHTTPMethods,
	}
}

// parse decodes a resource definition
func (r *Resource) parse(resource string) (*Resource, error) {
	if resource == "" {
		return nil, errors.New("the resource has no options")
	}
	for _, x := range strings.Split(resource, "|") {
		kp := strings.Split(x, "=")
		if len(kp) != 2 {
			return nil, errors.New("invalid resource keypair, should be (uri|uris|roles|methods|white-listed)=comma_values")
		}
		switch kp[0] {
		case "uri":
			r.URL = kp[1]
			if !strings.HasPrefix(r.URL, "/") {
				return nil, errors.New("the resource uri should start with a '/'")
			}
		case "uris":
			r.URLs = strings.Split(kp[1], ",")
			for _, u := range r.URLs {
				if !strings.HasPrefix(u, "/") {
					return nil, errors.New("the resource uri should start with a '/'")
				}

			}
		case "methods":
			r.Methods = strings.Split(kp[1], ",")
			if len(r.Methods) == 1 {
				if strings.EqualFold(r.Methods[0], anyMethod) {
					r.Methods = allHTTPMethods
				}
			}
		case "require-any-role":
			v, err := strconv.ParseBool(kp[1])
			if err != nil {
				return nil, err
			}
			r.RequireAnyRole = v
		case "roles":
			r.Roles = strings.Split(kp[1], ",")
		case "groups":
			r.Groups = strings.Split(kp[1], ",")
		case "white-listed":
			value, err := strconv.ParseBool(kp[1])
			if err != nil {
				return nil, errors.New("the value of whitelisted must be true|TRUE|T or it's false equivalent")
			}
			r.WhiteListed = value
		case "upstream-url":
			r.Upstream = kp[1]
		case "strip-basepath":
			r.StripBasePath = kp[1]
		case "enable-csrf":
			v, err := strconv.ParseBool(kp[1])
			if err != nil {
				return nil, errors.New("the value of enable-csrf must be true|TRUE|T or it's false equivalent")
			}
			r.EnableCSRF = v
		default:
			return nil, errors.New("invalid identifier, should be roles, uri or methods")
		}
	}

	return r, nil
}

// valid ensure the resource is valid
func (r *Resource) valid() error {
	if r.Methods == nil {
		r.Methods = make([]string, 0)
	}
	if r.Roles == nil {
		r.Roles = make([]string, 0)
	}
	if r.URL != "" && len(r.URLs) > 0 {
		return errors.New("can't specify both uri and uris")
	}
	if r.URL == "" && len(r.URLs) == 0 {
		return errors.New("resource does not have url")
	}
	if r.URL == "" && len(r.URLs) > 0 {
		for _, u := range r.URLs {
			if u == "" {
				return errors.New("resource does not have url")
			}
		}
	}
	if strings.HasSuffix(r.URL, "/") && !r.WhiteListed {
		return fmt.Errorf("you need a wildcard on the url resource to cover all request i.e. --resources=uri=%s*", r.URL)
	}
	if r.Upstream != "" {
		if _, err := url.Parse(r.Upstream); err != nil {
			return fmt.Errorf("upstream specified for resource %s is not a valid URL: %q", r.URL, r.Upstream)
		}
	}

	// step: add any of no methods
	if len(r.Methods) == 0 {
		r.Methods = allHTTPMethods
	}
	// step: check the method is valid
	for _, m := range r.Methods {
		if !isValidHTTPMethod(m) {
			return fmt.Errorf("invalid method %s", m)
		}
	}

	return nil
}

// getRoles returns a list of roles for this resource
func (r Resource) getRoles() string {
	return strings.Join(r.Roles, ",")
}

// String returns a string representation of the resource
func (r Resource) String() string {
	if r.WhiteListed {
		return fmt.Sprintf("uri: %s, white-listed", r.URL)
	}

	roles := "authentication only"
	methods := anyMethod

	if len(r.Roles) > 0 {
		roles = strings.Join(r.Roles, ",")
	}

	if len(r.Methods) > 0 {
		methods = strings.Join(r.Methods, ",")
	}

	return fmt.Sprintf("uri: %s, methods: %s, required: %s", r.URL, methods, roles)
}

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
	"time"

	"github.com/coreos/go-oidc/jose"
)

// userContext represents a user
type userContext struct {
	// the id of the user
	id string
	// the email associated to the user
	email string
	// a name of the user
	name string
	// the preferred name
	preferredName string
	// the expiration of the access token
	expiresAt time.Time
	// a set of roles associated
	roles []string
	// the audience for the token
	audience string
	// the access token itself
	token jose.JWT
	// the claims associated to the token
	claims jose.Claims
	// whether the context is from a session cookie or authorization header
	bearerToken bool
}

// isAudience checks the audience
func (r userContext) isAudience(aud string) bool {
	if r.audience == aud {
		return true
	}

	return false
}

// getRoles returns a list of roles
func (r userContext) getRoles() string {
	return strings.Join(r.roles, ",")
}

// isExpired checks if the token has expired
func (r userContext) isExpired() bool {
	return r.expiresAt.Before(time.Now())
}

// isBearerToken checks if the token
func (r userContext) isBearerToken() bool {
	return r.bearerToken
}

func (r userContext) String() string {
	return fmt.Sprintf("user: %s, expires: %s, roles: %s", r.preferredName, r.expiresAt.String(),
		strings.Join(r.roles, ","))
}

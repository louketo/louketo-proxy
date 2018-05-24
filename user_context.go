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

	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oidc"
)

// extractIdentity parse the jwt token and extracts the various elements is order to construct
func extractIdentity(token jose.JWT) (*userContext, error) {
	claims, err := token.Claims()
	if err != nil {
		return nil, err
	}
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName, found, err := claims.StringClaim(claimPreferredName)
	if err != nil || !found {
		preferredName = identity.Email
	}
	audience, found, err := claims.StringClaim(claimAudience)
	if err != nil || !found {
		return nil, ErrNoTokenAudience
	}

	// @step: extract the realm roles
	var roleList []string
	if realmRoles, found := claims[claimRealmAccess].(map[string]interface{}); found {
		if roles, found := realmRoles[claimResourceRoles]; found {
			for _, r := range roles.([]interface{}) {
				roleList = append(roleList, fmt.Sprintf("%s", r))
			}
		}
	}

	// @step: extract the client roles from the access token
	if accesses, found := claims[claimResourceAccess].(map[string]interface{}); found {
		for name, list := range accesses {
			scopes := list.(map[string]interface{})
			if roles, found := scopes[claimResourceRoles]; found {
				for _, r := range roles.([]interface{}) {
					roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
				}
			}
		}
	}

	// @step: extract any group information from the tokens
	groups, _, err := claims.StringsClaim(claimGroups)
	if err != nil {
		return nil, err
	}

	return &userContext{
		audience:      audience,
		claims:        claims,
		email:         identity.Email,
		expiresAt:     identity.ExpiresAt,
		groups:        groups,
		id:            identity.ID,
		name:          preferredName,
		preferredName: preferredName,
		roles:         roleList,
		token:         token,
	}, nil
}

// isAudience checks the audience
func (r *userContext) isAudience(aud string) bool {
	return r.audience == aud
}

// getRoles returns a list of roles
func (r *userContext) getRoles() string {
	return strings.Join(r.roles, ",")
}

// isExpired checks if the token has expired
func (r *userContext) isExpired() bool {
	return r.expiresAt.Before(time.Now())
}

// isBearer checks if the token
func (r *userContext) isBearer() bool {
	return r.bearerToken
}

// isCookie checks if it's by a cookie
func (r *userContext) isCookie() bool {
	return !r.isBearer()
}

// String returns a string representation of the user context
func (r *userContext) String() string {
	return fmt.Sprintf("user: %s, expires: %s, roles: %s", r.preferredName, r.expiresAt.String(), strings.Join(r.roles, ","))
}

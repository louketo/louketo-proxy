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
	"strings"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
)

// refreshAccessToken attempts to refresh the access token, returning the parsed token and the time it expires or a error
func (r *keycloakProxy) refreshAccessToken(refreshToken string) (jose.JWT, time.Time, error) {
	// step: refresh the access token
	response, err := r.getToken(oauth2.GrantTypeRefreshToken, refreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "token expired") {
			return jose.JWT{}, time.Time{}, ErrRefreshTokenExpired
		}
		return jose.JWT{}, time.Time{}, err
	}

	// step: parse the access token
	token, identity, err := r.parseToken(response.AccessToken)
	if err != nil {
		return jose.JWT{}, time.Time{}, err
	}

	return token, identity.ExpiresAt, nil
}

// parseToken retrieve the user identity from the token
func (r *keycloakProxy) parseToken(accessToken string) (jose.JWT, *oidc.Identity, error) {
	// step: parse and return the token
	token, err := jose.ParseJWT(accessToken)
	if err != nil {
		return jose.JWT{}, nil, err
	}

	// step: parse the claims
	claims, err := token.Claims()
	if err != nil {
		return jose.JWT{}, nil, err
	}

	// step: get the identity
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return jose.JWT{}, nil, err
	}

	return token, identity, nil
}

// verifyToken verify that the token in the user context is valid
func (r *keycloakProxy) verifyToken(token jose.JWT) error {
	// step: verify the token is whom they say they are
	if err := r.openIDClient.VerifyJWT(token); err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return ErrAccessTokenExpired
		}

		return err
	}

	return nil
}

// getToken retrieves a code from the provider, extracts and verified the token
func (r *keycloakProxy) getToken(grantType, code string) (oauth2.TokenResponse, error) {
	var response oauth2.TokenResponse

	// step: retrieve the client
	client, err := r.openIDClient.OAuthClient()
	if err != nil {
		return response, err
	}

	// step: request a token from the authentication server
	response, err = client.RequestToken(grantType, code)
	if err != nil {
		return response, err
	}

	return response, nil
}

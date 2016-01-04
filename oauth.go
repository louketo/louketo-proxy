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
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oauth2"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

//
// The handlers for managing the OAuth authentication flow
//

// authorizationHandler is responsible for performing the redirection to keycloak service
func (r *KeycloakProxy) authorizationHandler(cx *gin.Context) {

	// step: grab the oauth client
	oac, err := r.openIDClient.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to retrieve the oauth client")
		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// step: get the access type required
	accessType := ""
	if r.config.RefreshSession {
		accessType = "offline"
	}

	// step: build the redirection url to the authentication server
	redirectionURL := oac.AuthCodeURL(cx.Query("state"), accessType, "")

	// step: get the redirection url
	r.redirectToURL(redirectionURL, cx)
}

// callbackHandler is responsible for handling the response from keycloak
func (r *KeycloakProxy) callbackHandler(cx *gin.Context) {

	// step: ensure we have a authorization code
	code := cx.Request.URL.Query().Get("code")
	if code == "" {
		log.Error("failed to get the code callback request")
		r.accessForbidden(cx)
		return
	}

	// step: grab the state from request
	state := cx.Request.URL.Query().Get("state")
	if state == "" {
		state = "/"
	}

	// step: exchange the authorization for a access token
	response, err := r.getToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to retrieve access token from authentication service")
		r.accessForbidden(cx)
		return
	}

	// step: decode and parse the access token
	token, identity, err := r.parseToken(response.AccessToken)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to parse jwt token for identity")
		r.accessForbidden(cx)
		return
	}

	log.WithFields(log.Fields{
		"email":    identity.Email,
		"username": identity.Name,
		"expires":  identity.ExpiresAt,
	}).Infof("issuing a user session")

	// step: create a session from the access token
	if err := r.createSession(token, identity.ExpiresAt, cx); err != nil {
		log.Errorf("failed to inject the session token, error: %s", err)
		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// step: do we have session data to persist?
	if r.config.RefreshSession {
		// step: parse the token
		_, ident, err := r.parseToken(response.RefreshToken)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("failed to parse the refresh token")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		log.WithFields(log.Fields{
			"email":   identity.Email,
			"expires": identity.ExpiresAt,
		}).Infof("retrieved the refresh token for user")

		// step: create the state session
		state := &sessionState{
			refreshToken: response.RefreshToken,
		}

		maxSession := time.Now().Add(r.config.MaxSession)
		switch maxSession.After(ident.ExpiresAt) {
		case true:
			state.expireOn = ident.ExpiresAt
		default:
			state.expireOn = maxSession
		}

		if err := r.createSessionState(state, cx); err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("failed to inject the session state into request")

			cx.AbortWithStatus(http.StatusInternalServerError)

			return
		}
	}

	r.redirectToURL(state, cx)
}

// refreshAccessToken attempts to refresh the access token, returning the parsed token and the time it expires or a error
func (r *KeycloakProxy) refreshAccessToken(refreshToken string) (jose.JWT, time.Time, error) {
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
func (r *KeycloakProxy) parseToken(accessToken string) (jose.JWT, *oidc.Identity, error) {
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
func (r *KeycloakProxy) verifyToken(token jose.JWT) error {
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
func (r *KeycloakProxy) getToken(grantType, code string) (oauth2.TokenResponse, error) {
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

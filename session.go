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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

// refreshUserSessionToken is responsible for retrieving the session state cookie and attempting to
// refresh the access token for the user
func (r *KeycloakProxy) refreshUserSessionToken(cx *gin.Context) (jose.JWT, error) {
	// step: grab the session state cooke
	state, err := r.getSessionState(cx)
	if err != nil {
		return jose.JWT{}, ErrNoSessionStateFound
	}

	// step: has the refresh token expired
	if time.Now().After(state.expireOn) {
		glog.Warningf("failed to refresh the access token, the refresh token has expired, expiration: %s", state.expireOn)
		return jose.JWT{}, ErrAccessTokenExpired
	}

	// step: attempts to refresh the access token
	token, expires, err := r.refreshAccessToken(state.refreshToken)
	if err != nil {
		// step: has the refresh token expired
		if err == ErrRefreshTokenExpired {
			glog.Warningf("the refresh token has expired: %s", token)
			http.SetCookie(cx.Writer, createSessionStateCookie(token.Encode(), cx.Request.Host, time.Now()))
		}

		glog.Errorf("failed to refresh the access token, reason: %s", err)
		return jose.JWT{}, err
	}

	// step: inject the refreshed access token
	glog.V(10).Infof("injecting the refreshed access token into seesion, expires on: %s", expires)

	if err := r.createSession(token, expires, cx); err != nil {
		return token, err
	}

	return token, nil
}

// getSessionToken retrieves the authentication cookie from the request and parse's into a JWT token
func (r *KeycloakProxy) getSessionToken(cx *gin.Context) (jose.JWT, error) {
	// step: find the authentication cookie from the request
	cookie := findCookie(sessionCookieName, cx.Request.Cookies())
	if cookie == nil {
		return jose.JWT{}, ErrSessionNotFound
	}

	// step: parse the token
	jwt, err := jose.ParseJWT(cookie.Value)
	if err != nil {
		return jose.JWT{}, err
	}

	return jwt, nil
}

// getSessionState retrieves the session state from the request
func (r *KeycloakProxy) getSessionState(cx *gin.Context) (*SessionState, error) {
	// step: find the session data cookie
	cookie := findCookie(sessionStateCookieName, cx.Request.Cookies())
	if cookie == nil {
		return nil, ErrNoCookieFound
	}

	return r.decodeState(cookie.Value)
}

// getUserContext parse the jwt token and extracts the various elements is order to construct
// a UserContext for use
func (r *KeycloakProxy) getUserContext(token jose.JWT) (*UserContext, error) {
	// step: decode the claims from the tokens
	claims, err := token.Claims()
	if err != nil {
		return nil, err
	}

	// step: get the preferred name
	preferredName, _, err := claims.StringClaim("preferred_name")
	if err != nil {
		glog.Warningf("unable to extract the preferred name from the token claims, reason: %s", err)
	}

	// step: extract the identity
	ident, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}

	var list []string

	// step: extract the roles from the access token
	if accesses, found := claims["resource_access"].(map[string]interface{}); found {
		for roleName, roleList := range accesses {
			scopes := roleList.(map[string]interface{})
			if roles, found := scopes["roles"]; found {
				for _, r := range roles.([]interface{}) {
					list = append(list, fmt.Sprintf("%s:%s", roleName, r))
				}
			}
		}
	}

	return &UserContext{
		id:            ident.ID,
		name:          ident.Name,
		preferredName: preferredName,
		email:         ident.Email,
		expiresAt:     ident.ExpiresAt,
		roles:         list,
		token:         token,
		claims:        claims,
	}, nil
}

// createSession creates a session cookie with the access token
func (r *KeycloakProxy) createSession(token jose.JWT, expires time.Time, cx *gin.Context) error {
	glog.V(10).Infof("creating a user session cookie, expires on: %s, token: %s", expires, token)
	http.SetCookie(cx.Writer, createSessionCookie(token.Encode(), cx.Request.Host, expires))

	return nil
}

// createSessionState creates a session state cookie, used to hold the refresh cookie and the expiration time
func (r *KeycloakProxy) createSessionState(state *SessionState, cx *gin.Context) error {
	glog.V(10).Infof("creating a session state cookie, expires on: %s, token: %s", state.expireOn, state.refreshToken)

	// step: we need to encode the state
	encoded, err := r.encodeState(state)
	if err != nil {
		return err
	}
	// step: create a session state cookie
	http.SetCookie(cx.Writer, createSessionStateCookie(encoded, cx.Request.Host, state.expireOn))

	return nil
}

// encodeState encodes the session state information into a value for a cookie to consume
func (r *KeycloakProxy) encodeState(session *SessionState) (string, error) {
	// step: encode the session into a string
	encoded := fmt.Sprintf("%d|%s", session.expireOn.Unix(), session.refreshToken)

	// step: encrypt the cookie
	cipherText, err := encryptDataBlock([]byte(encoded), []byte(r.config.EncryptionKey))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// decodeState decodes the session state cookie value
func (r *KeycloakProxy) decodeState(state string) (*SessionState, error) {
	// step: decode the base64 encrypted cookie
	cipherText, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return nil, err
	}

	// step: decrypt the cookie back in the expiration|token
	plainText, err := decryptDataBlock(cipherText, []byte(r.config.EncryptionKey))
	if err != nil {
		return nil, ErrInvalidSession
	}

	// step: extracts the sections from the state
	sections := strings.Split(string(plainText), "|")
	if len(sections) != 2 {
		return nil, ErrInvalidSession
	}

	// step: convert the unit timestamp
	expiration, err := convertUnixTime(sections[0])
	if err != nil {
		return nil, ErrInvalidSession
	}

	return &SessionState{
		expireOn:     expiration,
		refreshToken: sections[1],
	}, nil
}

// createSessionCookie creates a new session cookie
func createSessionCookie(token, hostname string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Domain:   strings.Split(hostname, ":")[0],
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Value:    token,
	}
}

// createSessionStateCookie creates a new session state cookie
func createSessionStateCookie(token, hostname string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     sessionStateCookieName,
		Domain:   strings.Split(hostname, ":")[0],
		Path:     "/",
		HttpOnly: true,
		//Secure:   true,
		Value: token,
	}
}

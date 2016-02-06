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

	log "github.com/Sirupsen/logrus"
	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

const (
	claimPreferredName  = "preferred_username"
	claimAudience       = "aud"
	claimResourceAccess = "resource_access"
	claimResourceRoles  = "roles"
)

// sessionState holds the state related data
type sessionState struct {
	// the max time the session is permitted
	expireOn time.Time
	// the refresh token if any
	refreshToken string
}

// refreshUserSessionToken is responsible for retrieving the session state cookie and attempting to
// refresh the access token for the user
func (r *openIDProxy) refreshUserSessionToken(cx *gin.Context) (jose.JWT, error) {
	// step: grab the session state cooke
	state, err := r.getSessionState(cx)
	if err != nil {
		return jose.JWT{}, ErrNoSessionStateFound
	}

	// step: has the refresh token expired
	if time.Now().After(state.expireOn) {
		log.Warningf("failed to refresh the access token, the refresh token has expired, expiration: %s", state.expireOn)
		return jose.JWT{}, ErrAccessTokenExpired
	}

	// step: attempts to refresh the access token
	token, expires, err := r.refreshAccessToken(state.refreshToken)
	if err != nil {
		// step: has the refresh token expired
		if err == ErrRefreshTokenExpired {
			log.WithFields(log.Fields{"token": token}).Warningf("the refresh token has expired")
			// clear the session
			clearSessionState(cx)
		}

		log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")

		return jose.JWT{}, err
	}

	// step: inject the refreshed access token
	log.Infof("injecting the refreshed access token into seesion, expires on: %s", expires)

	// step: create the session
	if err := r.createSession(token, expires, cx); err != nil {
		return token, err
	}

	return token, nil
}

// getSessionToken retrieves the authentication cookie from the request and parse's into a JWT token
// The token can come either a session cookie or a Bearer header
func (r *openIDProxy) getSessionToken(cx *gin.Context) (jose.JWT, bool, error) {
	var session string

	isBearer := false
	// step: look for a authorization header
	if authHeader := cx.Request.Header.Get(authorizationHeader); authHeader != "" {
		isBearer = true
		items := strings.Split(authHeader, " ")
		if len(items) != 2 {
			return jose.JWT{}, isBearer, fmt.Errorf("invalid authorizarion header")
		}
		session = items[1]
	} else {
		// step: find the authentication cookie from the request
		cookie := findCookie(sessionCookieName, cx.Request.Cookies())
		if cookie == nil {
			return jose.JWT{}, isBearer, ErrSessionNotFound
		}
		session = cookie.Value
	}

	// step: parse the token
	jwt, err := jose.ParseJWT(session)
	if err != nil {
		return jose.JWT{}, isBearer, err
	}

	return jwt, isBearer, nil
}

// getSessionState retrieves the session state from the request
func (r *openIDProxy) getSessionState(cx *gin.Context) (*sessionState, error) {
	// step: find the session data cookie
	cookie := findCookie(sessionStateCookieName, cx.Request.Cookies())
	if cookie == nil {
		return nil, ErrNoCookieFound
	}

	return r.decodeState(cookie.Value)
}

// getUserContext parse the jwt token and extracts the various elements is order to construct
func (r *openIDProxy) getUserContext(token jose.JWT) (*userContext, error) {
	// step: decode the claims from the tokens
	claims, err := token.Claims()
	if err != nil {
		return nil, err
	}

	// step: extract the identity
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName, found, err := claims.StringClaim(claimPreferredName)
	if err != nil || !found {
		// choice: set the preferredName to the Email if claim not found
		preferredName = identity.Email
	}

	// step: retrieve the audience from access token
	audience, found, err := claims.StringClaim(claimAudience)
	if err != nil || !found {
		return nil, fmt.Errorf("the access token does not container a audience claim")
	}

	var list []string

	// step: extract the roles from the access token
	if accesses, found := claims[claimResourceAccess].(map[string]interface{}); found {
		for roleName, roleList := range accesses {
			scopes := roleList.(map[string]interface{})
			if roles, found := scopes[claimResourceRoles]; found {
				for _, r := range roles.([]interface{}) {
					list = append(list, fmt.Sprintf("%s:%s", roleName, r))
				}
			}
		}
	}

	return &userContext{
		id:            identity.ID,
		name:          preferredName,
		audience:      audience,
		preferredName: preferredName,
		email:         identity.Email,
		expiresAt:     identity.ExpiresAt,
		roles:         list,
		token:         token,
		claims:        claims,
	}, nil
}

// createSession creates a session cookie with the access token
func (r *openIDProxy) createSession(token jose.JWT, expires time.Time, cx *gin.Context) error {
	http.SetCookie(cx.Writer, createSessionCookie(token.Encode(), cx.Request.Host, expires))

	return nil
}

// createSessionState creates a session state cookie, used to hold the refresh cookie and the expiration time
func (r *openIDProxy) createSessionState(state *sessionState, cx *gin.Context) error {
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
func (r *openIDProxy) encodeState(session *sessionState) (string, error) {
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
func (r *openIDProxy) decodeState(state string) (*sessionState, error) {
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

	return &sessionState{
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
		// Secure:   true,
		Value: token,
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

// clearSessionState clears the session cookie
func clearSessionState(cx *gin.Context) {
	http.SetCookie(cx.Writer, createSessionStateCookie("", cx.Request.Host, time.Now()))
}

// clearSession clears the session cookie
func clearSession(cx *gin.Context) {
	http.SetCookie(cx.Writer, createSessionCookie("", cx.Request.Host, time.Now()))
}

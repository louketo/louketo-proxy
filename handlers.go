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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

//
// oauthAuthorizationHandler is responsible for performing the redirection to oauth provider
//
func (r oauthProxy) oauthAuthorizationHandler(cx *gin.Context) {
	// step: we can skip all of this if were not verifying the token
	if r.config.SkipTokenVerification {
		cx.AbortWithStatus(http.StatusNotAcceptable)
		return
	}

	client, err := r.client.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to retrieve the oauth client for authorization")

		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// step: set the access type of the session
	accessType := ""
	if containedIn("offline", r.config.Scopes) {
		accessType = "offline"
	}

	log.WithFields(log.Fields{
		"client_ip":   cx.ClientIP(),
		"access_type": accessType,
	}).Infof("incoming authorization request from client address: %s", cx.ClientIP())

	redirectionURL := client.AuthCodeURL(cx.Query("state"), accessType, "")

	// step: if we have a custom sign in page, lets display that
	if r.config.hasCustomSignInPage() {
		// step: inject any custom tags into the context for the template
		model := make(map[string]string, 0)
		for k, v := range r.config.TagData {
			model[k] = v
		}
		model["redirect"] = redirectionURL

		cx.HTML(http.StatusOK, path.Base(r.config.SignInPage), model)
		return
	}

	r.redirectToURL(redirectionURL, cx)
}

//
// oauthCallbackHandler is responsible for handling the response from oauth service
//
func (r oauthProxy) oauthCallbackHandler(cx *gin.Context) {
	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		cx.AbortWithStatus(http.StatusNotAcceptable)
		return
	}

	code := cx.Request.URL.Query().Get("code")
	state := cx.Request.URL.Query().Get("state")

	// step: ensure we have a authorization code to exchange
	if code == "" {
		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// step: ensure we have a state or default to root /
	if state == "" {
		state = "/"
	}

	// step: exchange the authorization for a access token
	response, err := exchangeAuthenticationCode(r.client, code)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("unable to exchange code for access token")

		r.accessForbidden(cx)
		return
	}

	// step: parse decode the identity token
	session, identity, err := parseToken(response.IDToken)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("unable to parse id token for identity")

		r.accessForbidden(cx)
		return
	}

	// step: verify the token is valid
	if err := verifyToken(r.client, session); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("unable to verify the id token")

		r.accessForbidden(cx)
		return
	}

	// step: attempt to decode the access token else we default to the id token
	accessToken, id, err := parseToken(response.AccessToken)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("unable to parse the access token, using id token only")
	} else {
		session = accessToken
		identity = id
	}

	log.WithFields(log.Fields{
		"email":    identity.Email,
		"expires":  identity.ExpiresAt.Format(time.RFC822Z),
		"duration": identity.ExpiresAt.Sub(time.Now()).String(),
		"idle":     r.config.IdleDuration.String(),
	}).Infof("issuing a new access token for user, email: %s", identity.Email)

	// step: drop's a session cookie with the access token
	r.dropAccessTokenCookie(cx, session.Encode(), r.config.IdleDuration)

	// step: does the response has a refresh token and we are NOT ignore refresh tokens?
	if r.config.EnableRefreshTokens && response.RefreshToken != "" {
		// step: encrypt the refresh token
		encrypted, err := encodeText(response.RefreshToken, r.config.EncryptionKey)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("failed to encrypt the refresh token")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// step: create and inject the state session
		switch r.useStore() {
		case true:
			if err := r.StoreRefreshToken(session, encrypted); err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Warnf("failed to save the refresh token in the store")
			}
		default:
			r.dropRefreshTokenCookie(cx, encrypted, r.config.IdleDuration*2)
		}
	}

	r.redirectToURL(state, cx)
}

//
// loginHandler provide's a generic endpoint for clients to perform a user_credentials login to the provider
//
func (r oauthProxy) loginHandler(cx *gin.Context) {
	// step: parse the client credentials
	username := cx.Request.URL.Query().Get("username")
	password := cx.Request.URL.Query().Get("password")

	if username == "" || password == "" {
		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
		}).Errorf("the request does not have both username and password")

		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// step: get the client
	client, err := r.client.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
			"error":     err.Error(),
		}).Errorf("unable to create the oauth client for user_credentials request")

		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// step: request the access token via
	token, err := client.UserCredsToken(username, password)
	if err != nil {
		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
			"error":     err.Error(),
		}).Errorf("unable to request the access token via grant_type 'password'")

		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	cx.JSON(http.StatusOK, tokenResponse{
		IDToken:      token.IDToken,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    token.Expires,
		Scope:        token.Scope,
	})
}

//
// logoutHandler performs a logout
//  - if it's just a access token, the cookie is deleted
//  - if the user has a refresh token, the token is invalidated by the provider
//  - optionally, the user can be redirected by to a url
//
func (r oauthProxy) logoutHandler(cx *gin.Context) {
	// the user can specify a url to redirect the back to
	redirectURL := cx.Request.URL.Query().Get("redirect")

	// step: drop the access token
	user, err := r.getIdentity(cx)
	if err != nil {
		cx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// step: can either use the id token or the refresh token
	identityToken := user.token.Encode()
	if refresh, err := r.retrieveRefreshToken(cx, user); err == nil {
		identityToken = refresh
	}
	// step: delete all the cookies
	r.clearAllCookies(cx)

	// step: check if the user has a state session and if so, revoke it
	if r.useStore() {
		go func() {
			if err := r.DeleteRefreshToken(user.token); err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to remove the refresh token from store")
			}
		}()
	}

	// step: do we have a revocation endpoint?
	if r.config.RevocationEndpoint != "" {
		client, err := r.client.OAuthClient()
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to retrieve the openid client")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// step: add the authentication headers
		// @TODO need to add the authenticated request to go-oidc
		encodedID := url.QueryEscape(r.config.ClientID)
		encodedSecret := url.QueryEscape(r.config.ClientSecret)

		// step: construct the url for revocation
		request, err := http.NewRequest("POST", r.config.RevocationEndpoint,
			bytes.NewBufferString(fmt.Sprintf("refresh_token=%s", identityToken)))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to construct the revocation request")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// step: add the authentication headers and content-type
		request.SetBasicAuth(encodedID, encodedSecret)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// step: attempt to make the
		response, err := client.HttpClient().Do(request)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to post to revocation endpoint")

			return
		}

		// step: throw in a log
		if response.StatusCode != http.StatusNoContent {
			content, _ := ioutil.ReadAll(response.Body)
			log.WithFields(log.Fields{
				"status":   response.StatusCode,
				"response": fmt.Sprintf("%s", content),
			}).Errorf("invalid response from revocation endpoint")
		} else {
			log.WithFields(log.Fields{
				"user": user.email,
			}).Infof("successfully logged out of the endpoint")
		}
	}

	// step: should we redirect the user
	if redirectURL != "" {
		r.redirectToURL(redirectURL, cx)
		return
	}

	cx.AbortWithStatus(http.StatusOK)
}

//
// proxyHandler is responsible to proxy the requests on to the upstream endpoint
//
func (r oauthProxy) proxyHandler() gin.HandlerFunc {
	// step: we don't wanna do this every time, quicker to perform once
	customClaims := make(map[string]string)
	for _, x := range r.config.AddClaims {
		customClaims[x] = fmt.Sprintf("X-Auth-%s", toHeader(x))
	}

	return func(cx *gin.Context) {
		// step: double check, if enforce is true and no user context it's a internal error
		if _, found := cx.Get(cxEnforce); found {
			if _, found := cx.Get(userContextName); !found {
				log.Errorf("no user context found for a secure request")
				cx.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		}

		// step: retrieve the user context if any
		if user, found := cx.Get(userContextName); found {
			id := user.(*userContext)
			cx.Request.Header.Add("X-Auth-UserId", id.id)
			cx.Request.Header.Add("X-Auth-Subject", id.preferredName)
			cx.Request.Header.Add("X-Auth-Username", id.name)
			cx.Request.Header.Add("X-Auth-Email", id.email)
			cx.Request.Header.Add("X-Auth-ExpiresIn", id.expiresAt.String())
			cx.Request.Header.Add("X-Auth-Token", id.token.Encode())
			cx.Request.Header.Add("X-Auth-Roles", strings.Join(id.roles, ","))

			// step: inject any custom claims
			for claim, header := range customClaims {
				if claim, found := id.claims[claim]; found {
					cx.Request.Header.Add(header, fmt.Sprintf("%v", claim))
				}
			}
		}

		// step: add the default headers
		cx.Request.Header.Add("X-Forwarded-For", cx.Request.RemoteAddr)
		cx.Request.Header.Set("X-Forwarded-Agent", prog)
		cx.Request.Header.Set("X-Forwarded-Agent-Version", version)

		// step: is this connection upgrading?
		if isUpgradedConnection(cx.Request) {
			log.Debugf("upgrading the connnection to %s", cx.Request.Header.Get(headerUpgrade))
			if err := tryUpdateConnection(cx, r.endpoint); err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to upgrade the connection")

				cx.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			cx.Abort()

			return
		}

		/*
		Issue: https://github.com/golang/go/issues/7618

		The reverse proxy does not update the Host header of request, as it's assumed the upstream in on the
		same domain as the proxy. We could override the Director method, but the latter is easier
		*/
		cx.Request.Host = r.endpoint.Host

		r.upstream.ServeHTTP(cx.Writer, cx.Request)
	}
}

//
// expirationHandler checks if the token has expired
//
func (r *oauthProxy) expirationHandler(cx *gin.Context) {
	// step: get the access token from the request
	user, err := r.getIdentity(cx)
	if err != nil {
		cx.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	// step: check the access is not expired
	if user.isExpired() {
		cx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	cx.AbortWithStatus(http.StatusOK)
}

//
// tokenHandler display access token to screen
//
func (r *oauthProxy) tokenHandler(cx *gin.Context) {
	// step: extract the access token from the request
	user, err := r.getIdentity(cx)
	if err != nil {
		cx.AbortWithError(http.StatusBadRequest, fmt.Errorf("unable to retrieve session, error: %s", err))
		return
	}

	// step: write the json content
	cx.Writer.Header().Set("Content-Type", "application/json")
	cx.String(http.StatusOK, fmt.Sprintf("%s", user.token.Payload))
}

//
// healthHandler is a health check handler for the service
//
func (r *oauthProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}

//
// retrieveRefreshToken retrieves the refresh token from store or cookie
//
func (r oauthProxy) retrieveRefreshToken(cx *gin.Context, user *userContext) (string, error) {
	var token string
	var err error

	// step: get the refresh token from the store or cookie
	switch r.useStore() {
	case true:
		token, err = r.GetRefreshToken(user.token)
	default:
		token, err = r.getRefreshTokenFromCookie(cx)
	}

	// step: decode the cookie
	if err != nil {
		return token, err
	}

	return decodeText(token, r.config.EncryptionKey)
}

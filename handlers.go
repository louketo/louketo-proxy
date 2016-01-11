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
	"path"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gambol99/go-oidc/jose"
	"github.com/gambol99/go-oidc/oauth2"
	"github.com/gin-gonic/gin"
)

//
// The logic is broken into four handlers just to simplify the code
//
//  a) entrypointHandler checks if the the uri requires authentication
//  b) authenticationHandler verifies the access token
//  c) admissionHandler verifies that the token is authorized to access to uri resource
//  c) proxyHandler is responsible for handling the reverse proxy to the upstream endpoint
//

const authRequired = "AUTH_REQUIRED"

// loggingHandler is a custom http logger
func (r *KeycloakProxy) loggingHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		start := time.Now()
		cx.Next()
		latency := time.Now().Sub(start)

		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
			"method":    cx.Request.Method,
			"status":    cx.Writer.Status(),
			"path":      cx.Request.RequestURI,
			"latency":   latency,
		}).Infof("[%d] |%s| |%13v| %-5s %s", cx.Writer.Status(), cx.ClientIP(),
			latency, cx.Request.Method, cx.Request.URL.Path)
	}
}

// entrypointHandler checks to see if the request requires authentication
func (r *KeycloakProxy) entrypointHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: ensure we don't block oauth
		if strings.HasPrefix(cx.Request.RequestURI, oauthURL) {
			return
		}

		// step: check if authentication is required - gin doesn't support wildcard url, so we have have to use prefixes
		for _, resource := range r.config.Resources {
			if strings.HasPrefix(cx.Request.RequestURI, resource.URL) {
				if containedIn(cx.Request.Method, resource.Methods) {
					cx.Set(authRequired, true)
				} else if containedIn("ANY", resource.Methods) {
					cx.Set(authRequired, true)
				}

				break
			}
		}
	}
}

// authenticationHandler is responsible for verifying the access token
func (r *KeycloakProxy) authenticationHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		var session jose.JWT

		// step: is authentication required on this uri?
		if _, found := cx.Get(authRequired); !found {
			return
		}

		// step: retrieve the access token from the request
		session, isBearer, err := r.getSessionToken(cx)
		if err != nil {
			// step: there isn't a session cookie, do we have refresh session cookie?
			if err == ErrSessionNotFound && r.config.RefreshSession && !isBearer {
				session, err = r.refreshUserSessionToken(cx)
				if err != nil {
					log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
					r.redirectToAuthorization(cx)
					return
				}
			} else {
				log.Errorf("failed to get session redirecting for authorization")
				r.redirectToAuthorization(cx)
				return
			}
		}

		// step: retrieve the identity and inject in the context
		userContext, err := r.getUserContext(session)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to retrieve the identity from the token")

			r.redirectToAuthorization(cx)
			return
		}
		userContext.bearerToken = isBearer

		cx.Set(userContextName, userContext)

		// step: verify the access token
		if err := r.verifyToken(userContext.token); err != nil {
			// step: if the error post verification is anything other than a token expired error
			// we immediately throw an access forbidden - as there is something messed up in the token
			if err != ErrAccessTokenExpired {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("invalid access token")
				r.accessForbidden(cx)
				return
			}

			if isBearer {
				log.WithFields(log.Fields{
					"username": userContext.name,
					"expired_on" : userContext.expiresAt.String(),
				}).Errorf("the session has expired and we are using bearer token")
				r.redirectToAuthorization(cx)
				return
			}

			// step: are we refreshing the access tokens?
			if !r.config.RefreshSession {
				log.WithFields(log.Fields{
					"username": userContext.name,
					"expired_on" : userContext.expiresAt.String(),
				}).Errorf("the session has expired and token refreshing is disabled")
				r.redirectToAuthorization(cx)
				return
			}

			// step: attempt to refresh the access token
			if _, err := r.refreshUserSessionToken(cx); err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
				r.redirectToAuthorization(cx)
				return
			}
		}
	}
}

// admissionHandler is responsible checking the access token against the protected resource
func (r *KeycloakProxy) admissionHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: is authentication required on this
		if _, found := cx.Get(authRequired); !found {
			return
		}

		// step: grab the identity from the context
		uc, found := cx.Get(userContextName)
		if !found {
			panic("there is no identity in the request context")
		}

		identity := uc.(*userContext)

		// step: validate the roles assigned to this token is valid for the resource
		for _, resource := range r.config.Resources {
			// step: check if it starts with the resource prefix
			if strings.HasPrefix(cx.Request.RequestURI, resource.URL) {
				// step: we need to check the roles
				if roles := len(resource.RolesAllowed); roles > 0 {
					if !hasRoles(resource.RolesAllowed, identity.roles) {
						log.WithFields(log.Fields{
							"access":   "denied",
							"username": identity.name,
							"resource": resource.URL,
							"issued":   identity.roles,
						}).Warnf("access denied, invalid roles")
						r.accessForbidden(cx)

						return
					}
				}

				// step: if we have any claim matching, validate the tokens has the claims
				for claimName, match := range r.config.ClaimsMatch {
					// step: if the claim is NOT in the token, we access deny
					value, found, err := identity.claims.StringClaim(claimName)
					if err != nil {
						log.WithFields(log.Fields{
							"access":   "denied",
							"username": identity.name,
							"resource": resource.URL,
							"error":    err.Error(),
						}).Errorf("unable to extract the claim from token")
						r.accessForbidden(cx)

						return
					}

					if !found {
						log.WithFields(log.Fields{
							"access":   "denied",
							"username": identity.name,
							"resource": resource.URL,
							"claim":    claimName,
						}).Warnf("the token does not have the claim")
						r.accessForbidden(cx)

						return
					}

					// step: check the claim is the same
					if value != match {
						log.WithFields(log.Fields{
							"access":   "denied",
							"username": identity.name,
							"resource": resource.URL,
							"claim":    claimName,
							"issued":   value,
							"required": match,
						}).Warnf("the token claims does not match claim requirement")
						r.accessForbidden(cx)

						return
					}
				}

				log.WithFields(log.Fields{
					"access" :   "permitted",
					"username" : identity.name,
					"resource" : resource.URL,
					"expires" :  identity.expiresAt.Sub(time.Now()),
					"bearer" : identity.bearerToken,
				}).Debugf("resource access permitted: %s", cx.Request.RequestURI)

				return
			}
		}
	}
}

// proxyHandler is responsible to proxy the requests on to the upstream endpoint
func (r *KeycloakProxy) proxyHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: retrieve the user context
		if identity, found := cx.Get(userContextName); found {
			id := identity.(*userContext)
			cx.Request.Header.Add("KEYCLOAK_ID", id.id)
			cx.Request.Header.Add("KEYCLOAK_SUBJECT", id.preferredName)
			cx.Request.Header.Add("KEYCLOAK_USERNAME", id.name)
			cx.Request.Header.Add("KEYCLOAK_EMAIL", id.email)
			cx.Request.Header.Add("KEYCLOAK_EXPIRES_IN", id.expiresAt.String())
			cx.Request.Header.Add("KEYCLOAK_ACCESS_TOKEN", id.token.Encode())
			cx.Request.Header.Add("KEYCLOAK_ROLES", strings.Join(id.roles, ","))
		}

		// step: add the default headers
		cx.Request.Header.Set("X-Forwarded-For", cx.Request.RemoteAddr)
		cx.Request.Header.Set("X-Forwarded-Agent", "keycloak-proxy")

		// step: is this connection upgrading?
		if isUpgradedConnection(cx.Request) {
			log.Debugf("upgrading the connnection to %s", cx.Request.Header.Get(headerUpgrade))
			if err := r.tryUpdateConnection(cx); err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to upgrade the connection")

				cx.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			cx.Abort()

			return
		}

		r.proxy.ServeHTTP(cx.Writer, cx.Request)
	}
}

// ---
// The handlers for managing the OAuth authentication flow
// ---

// oauthAuthorizationHandler is responsible for performing the redirection to keycloak service
func (r *KeycloakProxy) oauthAuthorizationHandler(cx *gin.Context) {
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

	// step: if we have a custom sign in page, lets display that
	if r.config.hasSignInPage() {
		// add the redirection url
		model := make(map[string]string, 0)
		for k, v := range r.config.TagData {
			model[k] = v
		}
		model["redirect"] = redirectionURL

		cx.HTML(http.StatusOK, path.Base(r.config.SignInPage), model)
		return
	}

	// step: get the redirection url
	r.redirectToURL(redirectionURL, cx)
}

// oauthCallbackHandler is responsible for handling the response from keycloak
func (r *KeycloakProxy) oauthCallbackHandler(cx *gin.Context) {
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

// healthHandler is a health check handler for the service
func (r *KeycloakProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}

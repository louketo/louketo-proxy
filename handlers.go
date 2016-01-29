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
	"github.com/unrolled/secure"
)

//
// The logic is broken into four handlers just to simplify the code
//
//  a) entryPointHandler checks if the the uri requires authentication
//  b) authenticationHandler verifies the access token
//  c) admissionHandler verifies that the token is authorized to access to uri resource
//  c) proxyHandler is responsible for handling the reverse proxy to the upstream endpoint
//

const (
	// cxEnforce is the tag name for a request requiring
	cxEnforce = "Enforcing"
)

//
// loggingHandler is a custom http logger
//
func (r *KeycloakProxy) loggingHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		start := time.Now()
		cx.Next()
		latency := time.Now().Sub(start)

		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
			"method":    cx.Request.Method,
			"status":    cx.Writer.Status(),
			"path":      cx.Request.URL.Path,
			"latency":   latency.String(),
		}).Infof("[%d] |%s| |%10v| %-5s %s", cx.Writer.Status(), cx.ClientIP(), latency, cx.Request.Method, cx.Request.URL.Path)
	}
}

//
// securityHandler performs numerous security checks on the request
//
func (r *KeycloakProxy) securityHandler() gin.HandlerFunc {
	// step: create the security options
	secure := secure.New(secure.Options{
		AllowedHosts:       r.config.Hostnames,
		BrowserXssFilter:   true,
		ContentTypeNosniff: true,
		FrameDeny:          true,
	})

	return func(cx *gin.Context) {
		// step: pass through the security middleware
		if err := secure.Process(cx.Writer, cx.Request); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed security middleware")
			cx.Abort()
			return
		}
		// step: permit the request to continue
		cx.Next()
	}
}

//
// entrypointHandler checks to see if the request requires authentication
//
func (r *KeycloakProxy) entryPointHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		if strings.HasPrefix(cx.Request.URL.Path, oauthURL) {
			cx.Next()
			return
		}

		// step: check if authentication is required - gin doesn't support wildcard url, so we have have to use prefixes
		for _, resource := range r.config.Resources {
			if strings.HasPrefix(cx.Request.URL.Path, resource.URL) {
				// step: has the resource been white listed?
				if resource.WhiteListed {
					break
				}
				// step: inject the resource into the context, saves us from doing this again
				if containedIn(cx.Request.Method, resource.Methods) || containedIn("ANY", resource.Methods) {
					cx.Set(cxEnforce, resource)
				}
				break
			}
		}
		// step: pass into the authentication and admission handlers
		cx.Next()

		// step: check the request has not been aborted and if not, proxy request
		if !cx.IsAborted() {
			r.proxyHandler(cx)
		}
	}
}

//
// authenticationHandler is responsible for verifying the access token
//
//  steps:
//  - check if the request is protected and requires validation
//  - retrieve the access token from the cookie or authorization header, if there isn't a token, check
//    if there is a session state and use the refresh token to refresh access token
//  - extract the user context from the access token, ensuring the minimum claims
//  - validate the audience of the access token is directed to us
//  - inject the user context into the request context for later layers
//  - skip verification of the access token if enabled
//  - else we validate the access token against the keypair via openid client
//  - if everything is cool, move on, else thrown a redirect or forbidden
//
func (r *KeycloakProxy) authenticationHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		var session jose.JWT

		// step: is authentication required on this uri?
		if _, found := cx.Get(cxEnforce); !found {
			log.Debugf("skipping the authentication handler, resource not protected")
			cx.Next()
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
				log.Errorf("failed to get session redirecting for authorization, %s", err)
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

		// step: check the audience for the token is us
		if !userContext.isAudience(r.config.ClientID) {
			log.WithFields(log.Fields{
				"username":   userContext.name,
				"expired_on": userContext.expiresAt.String(),
				"issued":     userContext.audience,
				"clientid":   r.config.ClientID,
			}).Warnf("the access token audience is not us, redirecting back for authentication")

			r.redirectToAuthorization(cx)
			return
		}

		cx.Set(userContextName, userContext)

		// step: verify the access token
		if r.config.SkipTokenVerification {
			log.Warnf("token verification enabled, skipping verification process - FOR TESTING ONLY")
			if userContext.isExpired() {
				log.WithFields(log.Fields{
					"username":   userContext.name,
					"expired_on": userContext.expiresAt.String(),
				}).Errorf("the session has expired and verification switch off")

				r.redirectToAuthorization(cx)
			}

			return
		}

		if err := r.verifyToken(userContext.token); err != nil {
			fields := log.Fields{
				"username":   userContext.name,
				"expired_on": userContext.expiresAt.String(),
				"error" : err.Error(),
			}

			// step: if the error post verification is anything other than a token expired error
			// we immediately throw an access forbidden - as there is something messed up in the token
			if err != ErrAccessTokenExpired {
				log.WithFields(log.Fields{"error": err.Error()}).Errorf("access token has expired")
				r.accessForbidden(cx)
				return
			}

			if isBearer {
				log.WithFields(fields).Errorf("the session has expired and we are using bearer token")
				r.redirectToAuthorization(cx)
				return
			}

			// step: are we refreshing the access tokens?
			if !r.config.RefreshSession {
				log.WithFields(fields).Errorf("the session has expired and token refreshing is disabled")
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

		cx.Next()
	}
}

//
// admissionHandler is responsible checking the access token against the protected resource
//
// steps:
//  - check if authentication and validation is required
//  - if so, retrieve the resource and user from the request context
//  - if we have any roles requirements validate the roles exists in the access token
//  - if er have any claim requirements validate the claims are the same
//  - if everything is ok, we permit the request to pass through
//
func (r *KeycloakProxy) admissionHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: if authentication is required on this, grab the resource spec
		ur, found := cx.Get(cxEnforce)
		if !found {
			return
		}

		// step: grab the identity from the context
		uc, found := cx.Get(userContextName)
		if !found {
			panic("there is no identity in the request context")
		}

		resource := ur.(*Resource)
		identity := uc.(*userContext)

		// step: we need to check the roles
		if roles := len(resource.RolesAllowed); roles > 0 {
			if !hasRoles(resource.RolesAllowed, identity.roles) {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": identity.name,
					"resource": resource.URL,
					"required": resource.getRoles(),
				}).Warnf("access denied, invalid roles")

				r.accessForbidden(cx)

				return
			}
		}

		// step: if we have any claim matching, validate the tokens has the claims
		// @TODO we should probably convert the claim checks to regexs
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
			"access":   "permitted",
			"username": identity.name,
			"resource": resource.URL,
			"expires":  identity.expiresAt.Sub(time.Now()).String(),
			"bearer":   identity.bearerToken,
		}).Debugf("resource access permitted: %s", cx.Request.RequestURI)
	}
}

//
// proxyHandler is responsible to proxy the requests on to the upstream endpoint
//
func (r *KeycloakProxy) proxyHandler(cx *gin.Context) {
	// step: double check, if enforce is true and no user context it's a internal error
	if _, found := cx.Get(cxEnforce); found {
		if _, found := cx.Get(userContextName); !found {
			log.Errorf("no user context found for a secure request")
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	// step: retrieve the user context
	if identity, found := cx.Get(userContextName); found {
		id := identity.(*userContext)
		cx.Request.Header.Add("X-Auth-UserId", id.id)
		cx.Request.Header.Add("X-Auth-Subject", id.preferredName)
		cx.Request.Header.Add("X-Auth-Username", id.name)
		cx.Request.Header.Add("X-Auth-Email", id.email)
		cx.Request.Header.Add("X-Auth-ExpiresIn", id.expiresAt.String())
		cx.Request.Header.Add("X-Auth-Token", id.token.Encode())
		cx.Request.Header.Add("X-Auth-Roles", strings.Join(id.roles, ","))
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

// ---
// The handlers for managing the OAuth authentication flow
// ---

//
// oauthAuthorizationHandler is responsible for performing the redirection to keycloak service
//
func (r *KeycloakProxy) oauthAuthorizationHandler(cx *gin.Context) {
	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		r.accessForbidden(cx)
		return
	}

	log.WithFields(log.Fields{
		"client_ip": cx.ClientIP(),
	}).Infof("incoming authorization request")

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

//
// oauthCallbackHandler is responsible for handling the response from keycloak
//
func (r *KeycloakProxy) oauthCallbackHandler(cx *gin.Context) {
	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		r.accessForbidden(cx)
		return
	}

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
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to retrieve access token from authentication service")
		r.accessForbidden(cx)
		return
	}

	// step: decode and parse the access token
	token, identity, err := r.parseToken(response.AccessToken)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to parse jwt token for identity")
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
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to parse the refresh token")

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
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to inject the session state into request")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	r.redirectToURL(state, cx)
}

//
// healthHandler is a health check handler for the service
//
func (r *KeycloakProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}

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

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

//
// The logic is broken into four handlers just to simplify the code
//
//  a) authenticationHandler checks for a session cookie and if doesn't exists redirects to AS, verifies the token is valid and if required refreshes the token
//  b) admissionHandler verifies the access token has access to the resource
//  c) proxyHandler is responsible for handling the reverse proxy to the upstream endpoint
//

const (
	authRequired = "AUTH_REQUIRED"
)

// entrypointHandler checks to see if the request requires authentication
func (r *KeycloakProxy) entrypointHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		glog.V(10).Infof("entering the entrypoint handler, uri: %s", cx.Request.RequestURI)

		// check if authentication is required
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
		glog.V(10).Infof("entering the authentication handler, uri: %s", cx.Request.RequestURI)

		// step: is authentication required on this
		if _, found := cx.Get(authRequired); !found {
			return
		}

		// step: extract the token if there is one
		// a) if there is no token, we check for session state and if so, we try to refresh the token
		// b) there is no token or session state, we simple redirect to keycloak
		session, err := r.getSessionToken(cx)
		if err != nil {
			// step: there isn't a session cookie, do we have refresh session cookie?
			if err == ErrSessionNotFound && r.config.RefreshSession {
				session, err = r.refreshUserSessionToken(cx)
				if err != nil {
					glog.Errorf("failed to refresh the access token, reason: %s", err)
					r.redirectToAuthorization(cx)
					return
				}
			} else {
				glog.Errorf("failed to get session redirecting for authorization")
				r.redirectToAuthorization(cx)
				return
			}
		}

		// step: retrieve the identity and inject in the context
		userContext, err := r.getUserContext(session)
		if err != nil {
			glog.Errorf("failed to retrieve the identity from the token, reason: %s", err)
			r.redirectToAuthorization(cx)
			return
		}
		cx.Set(userContextName, userContext)

		// step: verify the access token
		if err := r.verifyToken(userContext.token); err != nil {
			// step: if the error post verification is anything other than a token expired error
			// we immediately throw an access forbidden - as there is something messed up in the token
			if err != ErrAccessTokenExpired {
				glog.Errorf("invalid access token, %s, reason: %s", userContext.token, err)
				r.accessForbidden(cx)
				return
			}

			// step: are we refreshing the access tokens?
			if !r.config.RefreshSession {
				glog.Errorf("the session has expired for user: %s and token refreshing is disabled", userContext)
				r.redirectToAuthorization(cx)
				return
			}

			// step: attempt to refresh the access token
			if _, err := r.refreshUserSessionToken(cx); err != nil {
				glog.Errorf("failed to refresh the access token, reason: %s", err)
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
		userContext, found := cx.Get(userContextName)
		if !found {
			panic("there is no identity in the request context")
		}

		identity := userContext.(*UserContext)

		// step: validate the roles assigned to this token is valid for the resource
		for _, resource := range r.config.Resources {
			// step: check if it starts with the resource prefix
			if strings.HasPrefix(cx.Request.RequestURI, resource.URL) {
				// step: do we have any roles or do we need authentication only
				if len(resource.RolesAllowed) <= 0 {
					glog.V(4).Infof("[allowed] resource: %s authentication only, expires in: %s", resource, identity.expiresAt.Sub(time.Now()))
					return
				}
				// step: we need to check the roles
				if !hasRoles(resource.RolesAllowed, identity.roles) {
					glog.Errorf("[denied] resource: %s invalid roles, issued: %s", resource, identity.roles)
					r.accessForbidden(cx)
					return
				}

				glog.V(10).Infof("[allowed] resource: %s, expires in: %s", resource, identity.expiresAt.Sub(time.Now()))
				return
			}
		}
	}
}

// proxyHandler is responsible to proxy the requests on to the upstream endpoint
func (r *KeycloakProxy) proxyHandler(cx *gin.Context) {

	// step: retrieve the user context
	identity, found := cx.Get(userContextName)
	if found {
		id := identity.(*UserContext)
		// step: inject the identity in the headers
		cx.Request.Header.Add("KEYCLOAK_SUBJECT", id.preferredName)
		cx.Request.Header.Add("KEYCLOAK_USERNAME", id.name)
		cx.Request.Header.Add("KEYCLOAK_EMAIL", id.email)
		cx.Request.Header.Add("KEYCLOAK_EXPIRES_IN", id.expiresAt.String())
		cx.Request.Header.Add("KEYCLOAK_ACCESS_TOKEN", id.token.Encode())
		cx.Request.Header.Add("KEYCLOAK_ROLES", strings.Join(id.roles, ","))
	}

	// step: add the default headers
	cx.Request.Header.Set("X-Forwarded-For", cx.Request.RemoteAddr)

	// step: is this connection upgrading?
	if isUpgradedConnection(cx.Request) {
		glog.V(10).Infof("upgrading the connnection to %s", cx.Request.Header.Get(headerUpgrade))
		if err := r.tryUpdateConnection(cx); err != nil {
			glog.Errorf("failed to upgrade the connection, identity: %s, reason: %s", identity, err)
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		cx.Abort()

		return
	}

	r.proxy.ServeHTTP(cx.Writer, cx.Request)
}

// signInHandler is a handler for display a custom sign-in page to the user before redirecting to keycloak
func (r *KeycloakProxy) signInHandler(cx *gin.Context) {

}

// forbiddenAccessHandler is a handler for display a custom forbidden access page
func (r *KeycloakProxy) forbiddenAccessHandler(cx *gin.Context) {

}

// healthHandler is a health check handler for the service
func (r *KeycloakProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}

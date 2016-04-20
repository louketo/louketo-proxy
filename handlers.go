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
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
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
func (r *keycloakProxy) loggingHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		start := time.Now()
		cx.Next()
		latency := time.Now().Sub(start)

		log.WithFields(log.Fields{
			"client_ip": cx.ClientIP(),
			"method":    cx.Request.Method,
			"status":    cx.Writer.Status(),
			"bytes":     cx.Writer.Size(),
			"path":      cx.Request.URL.Path,
			"latency":   latency.String(),
		}).Infof("[%d] |%s| |%10v| %-5s %s", cx.Writer.Status(), cx.ClientIP(), latency, cx.Request.Method, cx.Request.URL.Path)
	}
}

//
// securityHandler performs numerous security checks on the request
//
func (r *keycloakProxy) securityHandler() gin.HandlerFunc {
	// step: create the security options
	secure := secure.New(secure.Options{
		AllowedHosts:         r.config.Hostnames,
		BrowserXssFilter:     true,
		ContentTypeNosniff:   true,
		FrameDeny:            true,
		STSIncludeSubdomains: true,
		STSSeconds:           31536000,
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
// entryPointHandler checks to see if the request requires authentication
//
func (r *keycloakProxy) entryPointHandler() gin.HandlerFunc {
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

		// step: add a custom headers to the request
		for k, v := range r.config.Header {
			cx.Request.Header.Set(k, v)
		}

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
func (r *keycloakProxy) authenticationHandler() gin.HandlerFunc {
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
			if err == ErrSessionNotFound && r.config.RefreshSessions && !isBearer {
				session, err = r.refreshUserSessionToken(cx)
				if err != nil {
					log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
					r.redirectToAuthorization(cx)
					return
				}
			} else {
				log.Errorf("failed to get session, redirecting for authorization, %s", err)
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

		log.Debugf("found user context: %s", userContext)

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
				"error":      err.Error(),
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
			if !r.config.RefreshSessions {
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
func (r *keycloakProxy) admissionHandler() gin.HandlerFunc {
	// step: compile the regex's for the claims
	claimMatches := make(map[string]*regexp.Regexp, 0)
	for k, v := range r.config.ClaimsMatch {
		claimMatches[k] = regexp.MustCompile(v)
	}

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
		if roles := len(resource.Roles); roles > 0 {
			if !hasRoles(resource.Roles, identity.roles) {
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
		for claimName, match := range claimMatches {
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
			if !match.MatchString(value) {
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
func (r *keycloakProxy) proxyHandler(cx *gin.Context) {
	// step: double check, if enforce is true and no user context it's a internal error
	if _, found := cx.Get(cxEnforce); found {
		if _, found := cx.Get(userContextName); !found {
			log.Errorf("no user context found for a secure request")
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	// step: retrieve the user context if any
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
	cx.Request.Header.Add("X-Forwarded-For", cx.Request.RemoteAddr)
	cx.Request.Header.Set("X-Forwarded-Agent", prog)
	cx.Request.Header.Set("X-Forwarded-Agent-Version", version)

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
func (r *keycloakProxy) oauthAuthorizationHandler(cx *gin.Context) {
	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		r.accessForbidden(cx)
		return
	}

	// step: grab the oauth client
	oac, err := r.openIDClient.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to retrieve the oauth client")
		cx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	// step: set the grant type of the session
	accessType := ""
	if r.config.RefreshSessions {
		accessType = "offline"
	}

	log.WithFields(log.Fields{
		"client_ip":   cx.ClientIP(),
		"access_type": accessType,
	}).Infof("incoming authorization request from client address: %s", cx.ClientIP())

	// step: build the redirection url to the authentication server
	redirectionURL := oac.AuthCodeURL(cx.Query("state"), accessType, "")

	// step: if we have a custom sign in page, lets display that
	if r.config.hasSignInPage() {
		// step: add the redirection url
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
func (r *keycloakProxy) oauthCallbackHandler(cx *gin.Context) {
	// step: is token verification switched on?
	if r.config.SkipTokenVerification {
		r.accessForbidden(cx)
		return
	}

	// step: get the code and state
	code := cx.Request.URL.Query().Get("code")
	state := cx.Request.URL.Query().Get("state")

	// step: ensure we have a authorization code to exchange
	if code == "" {
		log.WithFields(log.Fields{"client_ip": cx.ClientIP()}).Error("code parameter missing in callback")

		r.accessForbidden(cx)
		return
	}

	// step: ensure we have a state or default to root /
	if state == "" {
		state = "/"
	}

	// step: exchange the authorization for a access token
	response, err := r.getToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to exchange code for access token")
		r.accessForbidden(cx)
		return
	}

	// step: parse decode the identity token
	token, identity, err := r.parseToken(response.IDToken)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to parse id token for identity")
		r.accessForbidden(cx)
		return
	}
	// step: verify the token is valid
	if err := r.verifyToken(token); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to verify the id token")
		r.accessForbidden(cx)
		return
	}

	// step: attempt to decode the access token?
	ac, id, err := r.parseToken(response.AccessToken)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("unable to parse the access token, using id token only")
	} else {
		token = ac
		identity = id
	}

	log.WithFields(log.Fields{
		"email":   identity.Email,
		"expires": identity.ExpiresAt,
	}).Infof("issuing a user session")

	// step: create a session from the access token
	if err := r.createSession(token, identity.ExpiresAt, cx); err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to inject the session token")
		cx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	// step: are we using refresh tokens?
	if r.config.RefreshSessions {
		// step: create the state session
		state := &sessionState{
			refreshToken: response.RefreshToken,
			expireOn:     time.Now().Add(r.config.MaxSession),
		}

		// step: can we parse and extract the refresh token from the response
		// - note, the refresh token can be custom, i.e. doesn't have to be a jwt i.e. google for example
		_, refreshToken, err := r.parseToken(response.RefreshToken)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to parse refresh token (unknown format) using the as a static string")
		} else {
			// step: set the expiration of the refresh token.
			// - first we check if the duration exceeds the expiration of the refresh token
			if state.expireOn.After(refreshToken.ExpiresAt) {
				log.WithFields(log.Fields{
					"email":       refreshToken.Email,
					"max_session": r.config.MaxSession.String(),
					"duration":    state.expireOn.Format(time.RFC1123),
					"refresh":     refreshToken.ExpiresAt.Format(time.RFC1123),
				}).Errorf("max session exceeds the expiration of the refresh token, defaulting to refresh token")
				state.expireOn = refreshToken.ExpiresAt
			}
		}
		// step: create and inject the state session
		if err := r.createSessionState(state, cx); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to inject the session state into request")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// step: some debugging is useful here
		log.WithFields(log.Fields{
			"email":      identity.Email,
			"client_ip":  cx.ClientIP(),
			"expires_in": state.expireOn.Sub(time.Now()).String(),
		}).Infof("successfully retrieve refresh token for client: %s", identity.Email)
	}

	r.redirectToURL(state, cx)
}

//
// logoutHandler performs a logout
//  - if it's just a access token, the cookie is deleted
//  - if the user has a refresh token, the token is invalidated by the provider
//  - optionally, the user can be redirected by to a url
//
func (r keycloakProxy) logoutHandler(cx *gin.Context) {
	// the user can specify a url to redirect the back to
	redirectURL := cx.Request.URL.Query().Get("redirect")
	// step: drop the access token
	clearSession(cx)
	// step: check if the user has a state session and if so, revoke it
	state, err := r.getSessionState(cx)
	if err != nil {
		if err != ErrNoSessionStateFound {
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	} else {
		// step: clear the state session cookie
		clearSessionState(cx)
		// step: the user has a offline session, we need to revoke the access and invalidate the the offline token
		client, err := r.openIDClient.OAuthClient()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to retrieve the openid client")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// step: construct the url for revocation
		params := url.Values{}
		params.Add("refresh_token", state.refreshToken)
		params.Add("token", state.refreshToken)
		request, err := http.NewRequest("POST", r.config.RevocationEndpoint, nil)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to construct the revocation request")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		request.PostForm = params
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// step: attempt to make the
		response, err := client.HttpClient().Do(request)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("unable to post to revocation endpoint")
			return
		}
		if response.StatusCode != http.StatusOK {
			// step: read the response content
			content, _ := ioutil.ReadAll(response.Body)
			log.WithFields(log.Fields{
				"status":   response.StatusCode,
				"response": fmt.Sprintf("%s", content),
			}).Errorf("invalid response from revocation endpoint")
		}
	}
	if redirectURL != "" {
		r.redirectToURL(redirectURL, cx)
		return
	}

	cx.AbortWithStatus(http.StatusOK)
}

//
// expirationHandler checks if the token has expired
//
func (r *keycloakProxy) expirationHandler(cx *gin.Context) {
	// step: get the access token from the request
	token, err := r.getSession(cx)
	if err != nil {
		if err == ErrSessionNotFound {
			cx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		cx.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// step: decode the claims from the tokens
	claims, err := token.Claims()
	if err != nil {
		cx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("unable to extract the claims"))
		return
	}
	// step: extract the identity
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		cx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("unable to extract identity"))
		return
	}

	// step: check if token expired
	if time.Now().After(identity.ExpiresAt) {
		cx.AbortWithStatus(http.StatusForbidden)
	} else {
		cx.AbortWithStatus(http.StatusOK)
	}
}

//
// tokenHandler display access token to screen
//
func (r *keycloakProxy) tokenHandler(cx *gin.Context) {
	// step: extract the access token from the request
	token, err := r.getSession(cx)
	if err != nil {
		if err == ErrSessionNotFound {
			cx.AbortWithError(http.StatusOK, err)
			return
		}
		cx.AbortWithError(http.StatusInternalServerError, fmt.Errorf("unable to retrieve session, error: %s", err))
		return
	}

	// step: write the json content
	cx.Writer.Header().Set("Content-Type", "application/json")
	cx.String(http.StatusOK, fmt.Sprintf("%s", token.Payload))
}

//
// healthHandler is a health check handler for the service
//
func (r *keycloakProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}

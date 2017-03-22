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
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

// reverseProxyMiddleware is responsible for handles reverse proxy request to the upstream endpoint
func (r *oauthProxy) reverseProxyMiddleware() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: continue the flow
		cx.Next()
		// step: check its cool to continue
		if cx.IsAborted() {
			return
		}

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

		// By default goproxy only provides a forwarding proxy, thus all requests have to be absolute
		// and we must update the host headers
		cx.Request.URL.Host = r.endpoint.Host
		cx.Request.URL.Scheme = r.endpoint.Scheme
		cx.Request.Host = r.endpoint.Host

		r.upstream.ServeHTTP(cx.Writer, cx.Request)
	}
}

// forwardProxyHandler is responsible for signing outbound requests
func (r *oauthProxy) forwardProxyHandler() func(*http.Request, *http.Response) {
	// step: create oauth client
	client, err := r.client.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatal("failed to create an oauth client")
	}

	// step: the loop state
	var state struct {
		// the access token
		token jose.JWT
		// the refresh token if any
		refresh string
		// the identity of the user
		identity *oidc.Identity
		// the expiry time of the access token
		expiration time.Time
		// whether we need to login
		login bool
		// whether we should wait for expiration
		wait bool
	}
	state.login = true

	// step: create a routine to refresh the access tokens or login on expiration
	go func() {
		for {
			state.wait = false

			// step: do we have a access token
			if state.login {
				log.WithFields(log.Fields{
					"username": r.config.ForwardingUsername,
				}).Infof("requesting access token for user")

				// step: login into the service
				resp, err := client.UserCredsToken(r.config.ForwardingUsername, r.config.ForwardingPassword)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("failed to login to authentication service")

					// step: back-off and reschedule
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: parse the token
				token, identity, err := parseToken(resp.AccessToken)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Errorf("failed to parse the access token")

					// step: we should probably hope and reschedule here
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: update the loop state
				state.token = token
				state.identity = identity
				state.expiration = identity.ExpiresAt
				state.wait = true
				state.login = false
				state.refresh = resp.RefreshToken

				log.WithFields(log.Fields{
					"subject": state.identity.ID,
					"email":   state.identity.Email,
					"expires": state.expiration.Format(time.RFC3339),
				}).Infof("successfully retrieved access token for subject")

			} else {
				log.WithFields(log.Fields{
					"subject": state.identity.ID,
					"email":   state.identity.Email,
				}).Infof("access token is about to expiry")

				// step: if we a have a refresh token, we need to login again
				if state.refresh != "" {
					log.WithFields(log.Fields{
						"subject": state.identity.ID,
						"email":   state.identity.Email,
						"expires": state.expiration.Format(time.RFC3339),
					}).Infof("attempting to refresh the access token")

					// step: attempt to refresh the access
					token, expiration, err := getRefreshedToken(r.client, state.refresh)
					if err != nil {
						state.login = true
						switch err {
						case ErrRefreshTokenExpired:
							log.WithFields(log.Fields{
								"subject": state.identity.ID,
								"email":   state.identity.Email,
							}).Warningf("the refresh token has expired, need to login again")
						default:
							log.WithFields(log.Fields{
								"error": err.Error(),
							}).Errorf("failed to refresh the access token")
						}
						continue
					}

					// step: update the state
					state.token = token
					state.expiration = expiration
					state.wait = true
					state.login = false

					// step: add some debugging
					log.WithFields(log.Fields{
						"subject": state.identity.ID,
						"email":   state.identity.Email,
						"expires": state.expiration.Format(time.RFC3339),
					}).Infof("successfully refreshed the access token")

				} else {
					log.WithFields(log.Fields{
						"subject": state.identity.ID,
						"email":   state.identity.Email,
					}).Infof("session does not support refresh token, acquiring new token")

					// step: we don't have a refresh token, we must perform a login again
					state.wait = false
					state.login = true
				}
			}

			// step: wait for an expiration to come close
			if state.wait {
				// step: set the expiration of the access token within a random 85% of actual expiration
				duration := getWithin(state.expiration, 0.80)

				log.WithFields(log.Fields{
					"token_expiration": state.expiration.Format(time.RFC3339),
					"renewel_duration": duration.String(),
				}).Infof("waiting for expiration of access token")

				<-time.After(duration)
			}
		}
	}()

	return func(req *http.Request, resp *http.Response) {
		hostname := req.Host
		req.URL.Host = hostname

		// step: does the host being signed?
		if len(r.config.ForwardingDomains) == 0 || containsSubString(hostname, r.config.ForwardingDomains) {
			// step: sign the outbound request with the access token
			req.Header.Set("X-Forwarded-Agent", prog)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.token.Encode()))
		}
	}
}

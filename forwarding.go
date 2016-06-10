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

//
// upstreamReverseProxyHandler is responsible for handles reverse proxy request to the upstream endpoint
//
func (r *oauthProxy) upstreamReverseProxyHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
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
		/*
			By default goproxy only provides a forwarding proxy, thus all requests have to be absolute
			and we must update the host headers
		*/
		cx.Request.URL.Host = r.endpoint.Host
		cx.Request.URL.Scheme = r.endpoint.Scheme
		cx.Request.Host = r.endpoint.Host

		r.upstream.ServeHTTP(cx.Writer, cx.Request)
	}
}

//
// forwardProxyHandler is responsible for signing outbound requests
//
func (r *oauthProxy) forwardProxyHandler() gin.HandlerFunc {
	var token jose.JWT
	var identity *oidc.Identity
	var refreshToken string

	// step: create oauth client
	client, err := r.client.OAuthClient()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatalf("failed to create an oauth, error: %s", err)
	}

	// step: create a routine to refresh the access tokens or login on expiration
	go func() {
		// step: setup a timer to refresh the access token
		requireLogin := true
		var expires time.Time

		for {
			waitingOn := false

			// step: do we have a access token
			if requireLogin {
				log.WithFields(log.Fields{
					"username": r.config.ForwardingUsername,
				}).Debugf("requesting a access token for user")

				// step: login into the service
				resp, err := client.UserCredsToken(r.config.ForwardingUsername, r.config.ForwardingPassword)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Error("failed to login to authentication service")

					// step: backoff and reschedule
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: decode the token to find the claims
				token, err = jose.ParseJWT(resp.AccessToken)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Errorf("failed to parse the access token")

					// step: we should probably hope and reschedule here
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				claims, err := token.Claims()
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Errorf("failed to parse claims in access token")

					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: parse the identity from the token
				identity, err = oidc.IdentityFromClaims(claims)
				if err != nil {
					log.WithFields(log.Fields{
						"error": err.Error(),
					}).Errorf("failed to decode the identity of access token")

					// step: reschedule a reattempt in x seconds
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: print some logging for debug purposes
				// step: set the expiration of the access token within a random 85% of
				// actual expiration
				seconds := int(float64(identity.ExpiresAt.Sub(time.Now()).Seconds()) * 0.85)
				expires = time.Now().Add(time.Duration(seconds) * time.Second)

				// step: update the loop state
				requireLogin = false
				waitingOn = true
				refreshToken = resp.RefreshToken

				log.WithFields(log.Fields{
					"subject":    identity.ID,
					"email":      identity.Email,
					"expires_on": identity.ExpiresAt.Format(time.RFC822Z),
					"renewal":    expires.Format(time.RFC822Z),
					"duration":   expires.Sub(time.Now()).String(),
				}).Infof("retrieved the access token for subject")

			} else {
				// step: check if the access token is about to expiry
				if time.Now().After(expires) {
					log.WithFields(log.Fields{
						"subject": identity.ID,
						"email":   identity.Email,
					}).Debugf("access token is about to expiry")
					// step: if we do NOT have a refresh token, we need to login again
					if refreshToken == "" {
						waitingOn = false
						requireLogin = true
						break
					}
				}

				log.WithFields(log.Fields{
					"subject":    identity.ID,
					"email":      identity.Email,
					"expires_on": identity.ExpiresAt.Format(time.RFC822Z),
				}).Debugf("attempting to refresh the access token")

				// step: attempt to refresh the access
				renewToken, expiresIn, err := getRefreshedToken(r.client, refreshToken)
				if err != nil {
					// step: we need to login again
					requireLogin = true
					// step: has the refresh token expired
					switch err {
					case ErrRefreshTokenExpired:
						log.WithFields(log.Fields{
							"token": token,
						}).Warningf("the refresh token has expired, need to login again")
					default:
						log.WithFields(log.Fields{
							"error": err.Error(),
						}).Errorf("failed to refresh the access token")
					}
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: update the access token
				token = renewToken
				expires = expiresIn
				waitingOn = true
			}

			// step: wait for an expiration to come close
			if waitingOn {
				log.WithFields(log.Fields{
					"expires": expires.String(),
				}).Debugf("waiting for expiration of access token")

				<-time.After(expires.Sub(time.Now()))
			}
		}
	}()

	return func(cx *gin.Context) {
		hostname := cx.Request.Host
		cx.Request.URL.Host = cx.Request.Host

		// step: does the host being signed?
		// a) if the forwarding domain set and we are NOT in the list, just forward it
		// b) else the list is zero (meaning sign all requests) or we are in the list
		if len(r.config.ForwardingDomains) > 0 && !containsSubString(hostname, r.config.ForwardingDomains) {
			goto PROXY
		}

		// step: sign the outbound request with the access token
		cx.Request.Header.Add("X-Forwarded-Proto", cx.Request.URL.Scheme)
		cx.Request.Header.Set("X-Forwarded-Agent", prog)
		cx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))

	PROXY:
		r.upstream.ServeHTTP(cx.Writer, cx.Request)
	}
}

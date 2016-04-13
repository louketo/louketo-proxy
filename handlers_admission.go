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
	"regexp"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

//
// admissionHandler is responsible checking the access token against the protected resource
//
func (r *oauthProxy) admissionHandler() gin.HandlerFunc {
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
		user := uc.(*userContext)

		// step: check the audience for the token is us
		if !user.isAudience(r.config.ClientID) {
			log.WithFields(log.Fields{
				"username":   user.name,
				"expired_on": user.expiresAt.String(),
				"issued":     user.audience,
				"clientid":   r.config.ClientID,
			}).Warnf("the access token audience is not us, redirecting back for authentication")

			r.accessForbidden(cx)
			return
		}

		// step: we need to check the roles
		if roles := len(resource.Roles); roles > 0 {
			if !hasRoles(resource.Roles, user.roles) {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": user.name,
					"resource": resource.URL,
					"required": resource.GetRoles(),
				}).Warnf("access denied, invalid roles")

				r.accessForbidden(cx)
				return
			}
		}

		// step: if we have any claim matching, validate the tokens has the claims
		for claimName, match := range claimMatches {
			// step: if the claim is NOT in the token, we access deny
			value, found, err := user.claims.StringClaim(claimName)
			if err != nil {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": user.name,
					"resource": resource.URL,
					"error":    err.Error(),
				}).Errorf("unable to extract the claim from token")

				r.accessForbidden(cx)
				return
			}

			if !found {
				log.WithFields(log.Fields{
					"access":   "denied",
					"username": user.name,
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
					"username": user.name,
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
			"username": user.name,
			"resource": resource.URL,
			"expires":  user.expiresAt.Sub(time.Now()).String(),
		}).Debugf("resource access permitted: %s", cx.Request.RequestURI)
	}
}

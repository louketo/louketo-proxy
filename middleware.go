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
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/purell"
	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/unrolled/secure"
)

const (
	// cxEnforce is the tag name for a request requiring
	cxEnforce = "Enforcing"
)

const normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes

// filterMiddleware is custom filtering for incoming requests
func (r *oauthProxy) filterMiddleware() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: keep a copy of the original
		orig := cx.Request.URL.Path
		// step: normalize the url
		purell.NormalizeURL(cx.Request.URL, normalizeFlags)
		// step: continue the flow
		cx.Next()
		// step: place back the original
		cx.Request.URL.Path = orig
	}
}

// loggingMiddleware is a custom http logger
func (r *oauthProxy) loggingMiddleware() gin.HandlerFunc {
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

// metricsMiddleware is responsible for collecting metrics
func (r *oauthProxy) metricsMiddleware() gin.HandlerFunc {
	log.Infof("enabled the service metrics middleware, available on %s%s", oauthURL, metricsURL)

	statusMetrics := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_total",
			Help: "The HTTP requests broken partitioned by status code",
		},
		[]string{"code", "method"},
	)

	// step: register the metric with prometheus
	prometheus.MustRegisterOrGet(statusMetrics)

	return func(cx *gin.Context) {
		// step: permit to next stage
		cx.Next()
		// step: update the metrics
		statusMetrics.WithLabelValues(fmt.Sprintf("%d", cx.Writer.Status()), cx.Request.Method).Inc()
	}
}

// entrypointMiddleware checks to see if the request requires authentication
func (r *oauthProxy) entrypointMiddleware() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: we can skip if under oauth prefix
		if strings.HasPrefix(cx.Request.URL.Path, oauthURL) {
			return
		}

		// step: check if authentication is required - gin doesn't support wildcard url
		// so we have to use prefixes
		for _, resource := range r.config.Resources {
			if strings.HasPrefix(cx.Request.URL.Path, resource.URL) {
				if resource.WhiteListed {
					break
				}
				// step: inject the resource into the context, saves us from doing this again
				if containedIn("ANY", resource.Methods) || containedIn(cx.Request.Method, resource.Methods) {
					cx.Set(cxEnforce, resource)
				}
				break
			}
		}
	}
}

// authenticationMiddleware is responsible for verifying the access token
func (r *oauthProxy) authenticationMiddleware() gin.HandlerFunc {
	return func(cx *gin.Context) {
		// step: grab the client ip address - quicker to do once
		clientIP := cx.ClientIP()

		// step: is authentication required on this uri?
		if _, found := cx.Get(cxEnforce); !found {
			log.WithFields(log.Fields{
				"uri": cx.Request.URL.Path,
			}).Debugf("skipping the authentication as resource not protected")

			return
		}

		// step: grab the user identity from the request
		user, err := r.getIdentity(cx.Request)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Errorf("no session found in request, redirecting for authorization")

			r.redirectToAuthorization(cx)
			return
		}

		// step: inject the user into the context
		cx.Set(userContextName, user)

		// step: skipif we are running skip-token-verification
		if r.config.SkipTokenVerification {
			log.Warnf("skip token verification enabled, skipping verification process - FOR TESTING ONLY")

			if user.isExpired() {
				log.WithFields(log.Fields{
					"client_ip":  clientIP,
					"username":   user.name,
					"expired_on": user.expiresAt.String(),
				}).Errorf("the session has expired and verification switch off")

				r.redirectToAuthorization(cx)
			}

			return
		}

		if err := verifyToken(r.client, user.token); err != nil {
			// step: if the error post verification is anything other than a token expired error
			// we immediately throw an access forbidden - as there is something messed up in the token
			if err != ErrAccessTokenExpired {
				log.WithFields(log.Fields{
					"client_ip": clientIP,
					"error":     err.Error(),
				}).Errorf("access token failed verification")

				r.accessForbidden(cx)
				return
			}

			// step: check if we are refreshing the access tokens and if not re-auth
			if !r.config.EnableRefreshTokens {
				log.WithFields(log.Fields{
					"email":      user.name,
					"expired_on": user.expiresAt.String(),
					"client_ip":  clientIP,
				}).Errorf("session expired and access token refreshing is disabled")

				r.redirectToAuthorization(cx)
				return
			}

			log.WithFields(log.Fields{
				"email":     user.email,
				"client_ip": clientIP,
			}).Infof("accces token for user has expired, attemping to refresh the token")

			// step: check if the user has refresh token
			refresh, err := r.retrieveRefreshToken(cx.Request, user)
			if err != nil {
				log.WithFields(log.Fields{
					"email":     user.email,
					"error":     err.Error(),
					"client_ip": clientIP,
				}).Errorf("unable to find a refresh token for user")

				r.redirectToAuthorization(cx)
				return
			}

			// attempt to refresh the access token
			token, _, err := getRefreshedToken(r.client, refresh)
			if err != nil {
				switch err {
				case ErrRefreshTokenExpired:
					log.WithFields(log.Fields{
						"email":     user.email,
						"client_ip": clientIP,
					}).Warningf("refresh token has expired, cannot retrieve access token")

					r.clearAllCookies(cx)
				default:
					log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to refresh the access token")
				}

				r.redirectToAuthorization(cx)
				return
			}

			// get the expiration of the new access token
			expiresIn := r.getAccessCookieExpiration(token, refresh)

			log.WithFields(log.Fields{
				"client_ip":   clientIP,
				"cookie_name": r.config.CookieAccessName,
				"email":       user.email,
				"expires_in":  expiresIn.String(),
			}).Infof("injecting the refreshed access token cookie")

			// step: inject the refreshed access token
			r.dropAccessTokenCookie(cx, token.Encode(), expiresIn)

			if r.useStore() {
				go func(old, new jose.JWT, state string) {
					if err := r.DeleteRefreshToken(old); err != nil {
						log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to remove old token")
					}
					if err := r.StoreRefreshToken(new, state); err != nil {
						log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to store refresh token")
						return
					}
				}(user.token, token, refresh)
			}

			// step: update the with the new access token
			user.token = token

			// step: inject the user into the context
			cx.Set(userContextName, user)
		}

		cx.Next()
	}
}

// admissionMiddleware is responsible checking the access token against the protected resource
func (r *oauthProxy) admissionMiddleware() gin.HandlerFunc {
	// step: compile the regex's for the claims
	claimMatches := make(map[string]*regexp.Regexp, 0)
	for k, v := range r.config.MatchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(cx *gin.Context) {
		// step: is this resource enforcing?
		if _, found := cx.Get(cxEnforce); !found {
			return
		}

		resource := cx.MustGet(cxEnforce).(*Resource)
		user := cx.MustGet(userContextName).(*userContext)

		// step: check the audience for the token is us
		if r.config.ClientID != "" && !user.isAudience(r.config.ClientID) {
			log.WithFields(log.Fields{
				"email":      user.email,
				"expired_on": user.expiresAt.String(),
				"issuer":     user.audience,
				"client_id":  r.config.ClientID,
			}).Warnf("access token audience is not us, redirecting back for authentication")

			r.accessForbidden(cx)
			return
		}

		// step: we need to check the roles
		if roles := len(resource.Roles); roles > 0 {
			if !hasRoles(resource.Roles, user.roles) {
				log.WithFields(log.Fields{
					"access":   "denied",
					"email":    user.email,
					"resource": resource.URL,
					"required": resource.getRoles(),
				}).Warnf("access denied, invalid roles")

				r.accessForbidden(cx)
				return
			}
		}

		// step: if we have any claim matching, lets validate the tokens has the claims
		for claimName, match := range claimMatches {
			// step: if the claim is NOT in the token, we access deny
			value, found, err := user.claims.StringClaim(claimName)
			if err != nil {
				log.WithFields(log.Fields{
					"access":   "denied",
					"email":    user.email,
					"resource": resource.URL,
					"error":    err.Error(),
				}).Errorf("unable to extract the claim from token")

				r.accessForbidden(cx)
				return
			}

			if !found {
				log.WithFields(log.Fields{
					"access":   "denied",
					"email":    user.email,
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
					"email":    user.email,
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
			"email":    user.email,
			"resource": resource.URL,
			"expires":  user.expiresAt.Sub(time.Now()).String(),
		}).Debugf("access permitted to resource")
	}
}

// corsMiddleware injects the CORS headers, if set, for request made to /oauth
func (r *oauthProxy) corsMiddleware(c Cors) gin.HandlerFunc {
	return func(cx *gin.Context) {
		if len(c.Origins) > 0 {
			cx.Writer.Header().Set("Access-Control-Allow-Origin", strings.Join(c.Origins, ","))
		}
		if c.Credentials {
			cx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if len(c.ExposedHeaders) > 0 {
			cx.Writer.Header().Set("Access-Control-Expose-Headers", strings.Join(c.ExposedHeaders, ","))
		}
		if len(c.Methods) > 0 {
			cx.Writer.Header().Set("Access-Control-Allow-Methods", strings.Join(c.Methods, ","))
		}
		if len(c.Headers) > 0 {
			cx.Writer.Header().Set("Access-Control-Allow-Headers", strings.Join(c.Headers, ","))
		}
		if c.MaxAge > 0 {
			cx.Writer.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", int(c.MaxAge.Seconds())))
		}
	}
}

//
// headersMiddleware is responsible for add the authentication headers for the upstream
//
func (r *oauthProxy) headersMiddleware(custom []string) gin.HandlerFunc {
	// step: we don't wanna do this every time, quicker to perform once
	customClaims := make(map[string]string)
	for _, x := range custom {
		customClaims[x] = fmt.Sprintf("X-Auth-%s", toHeader(x))
	}

	return func(cx *gin.Context) {
		// step: add any custom headers to the request
		for k, v := range r.config.Headers {
			cx.Request.Header.Set(k, v)
		}

		// step: retrieve the user context if any
		if user, found := cx.Get(userContextName); found {
			id := user.(*userContext)

			cx.Request.Header.Set("X-Auth-Userid", id.name)
			cx.Request.Header.Set("X-Auth-Subject", id.id)
			cx.Request.Header.Set("X-Auth-Username", id.name)
			cx.Request.Header.Set("X-Auth-Email", id.email)
			cx.Request.Header.Set("X-Auth-ExpiresIn", id.expiresAt.String())
			cx.Request.Header.Set("X-Auth-Token", id.token.Encode())
			cx.Request.Header.Set("X-Auth-Roles", strings.Join(id.roles, ","))

			// step: add the authorization header if requested
			if r.config.EnableAuthorizationHeader {
				cx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", id.token.Encode()))
			}

			// step: inject any custom claims
			for claim, header := range customClaims {
				if claim, found := id.claims[claim]; found {
					cx.Request.Header.Set(header, fmt.Sprintf("%v", claim))
				}
			}
		}

		cx.Request.Header.Add("X-Forwarded-For", cx.Request.RemoteAddr)
		cx.Request.Header.Set("X-Forwarded-Host", cx.Request.Host)
		cx.Request.Header.Set("X-Forwarded-Proto", cx.Request.Header.Get("X-Forwarded-Proto"))
	}
}

// securityMiddleware performs numerous security checks on the request
func (r *oauthProxy) securityMiddleware() gin.HandlerFunc {
	log.Info("enabling the security filter middleware")
	// step: create the security options
	secure := secure.New(secure.Options{
		AllowedHosts:          r.config.Hostnames,
		BrowserXssFilter:      r.config.EnableBrowserXSSFilter,
		ContentSecurityPolicy: r.config.ContentSecurityPolicy,
		ContentTypeNosniff:    r.config.EnableContentNoSniff,
		FrameDeny:             r.config.EnableFrameDeny,
		SSLRedirect:           r.config.EnableHTTPSRedirect,
	})

	return func(cx *gin.Context) {
		if err := secure.Process(cx.Writer, cx.Request); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed security middleware")

			cx.Abort()
		}
	}
}

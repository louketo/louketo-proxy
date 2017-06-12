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
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/purell"
	"github.com/gambol99/go-oidc/jose"
	"github.com/labstack/echo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/unrolled/secure"
	"go.uber.org/zap"
)

const normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes

// proxyRevokeMiddleware is just a helper to drop all requests proxying
func (r *oauthProxy) proxyRevokeMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			r.revokeProxy(cx)
			cx.NoContent(http.StatusForbidden)
			return next(cx)
		}
	}
}

// filterMiddleware is custom filtering for incoming requests
func (r *oauthProxy) filterMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			// step: keep a copy of the original
			keep := cx.Request().URL.Path
			purell.NormalizeURL(cx.Request().URL, normalizeFlags)
			// step: ensure we have a slash in the url
			if !strings.HasPrefix(cx.Request().URL.Path, "/") {
				cx.Request().URL.Path = "/" + cx.Request().URL.Path
			}
			cx.Request().RequestURI = cx.Request().URL.RawPath
			cx.Request().URL.RawPath = cx.Request().URL.Path
			// step: continue the flow
			next(cx)
			// step: place back the original uri for proxying request
			cx.Request().URL.Path = keep
			cx.Request().URL.RawPath = keep
			cx.Request().RequestURI = keep

			return nil
		}
	}
}

// loggingMiddleware is a custom http logger
func (r *oauthProxy) loggingMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			start := time.Now()
			next(cx)
			latency := time.Since(start)
			addr := cx.RealIP()
			//msg := .Infof("[%d] |%s| |%10v| %-5s %s", cx.Response().Status, addr, latency, cx.Request().Method, cx.Request().URL.Path)
			r.log.Info("client request",
				zap.Int("response", cx.Response().Status),
				zap.String("path", cx.Request().URL.Path),
				zap.String("client_ip", addr),
				zap.String("method", cx.Request().Method),
				zap.Int("status", cx.Response().Status),
				zap.Int64("bytes", cx.Response().Size),
				zap.String("path", cx.Request().URL.Path),
				zap.String("latency", latency.String()))

			return nil
		}
	}
}

// metricsMiddleware is responsible for collecting metrics
func (r *oauthProxy) metricsMiddleware() echo.MiddlewareFunc {
	r.log.Info("enabled the service metrics middleware, available on",
		zap.String("path", fmt.Sprintf("%s%s", oauthURL, metricsURL)))

	statusMetrics := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_total",
			Help: "The HTTP requests partitioned by status code",
		},
		[]string{"code", "method"},
	)
	prometheus.MustRegister(statusMetrics)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			statusMetrics.WithLabelValues(fmt.Sprintf("%d", cx.Response().Status), cx.Request().Method).Inc()
			return next(cx)
		}
	}
}

// authenticationMiddleware is responsible for verifying the access token
func (r *oauthProxy) authenticationMiddleware(resource *Resource) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			clientIP := cx.RealIP()

			// step: grab the user identity from the request
			user, err := r.getIdentity(cx.Request())
			if err != nil {
				r.log.Error("no session found in request, redirecting for authorization", zap.Error(err))
				return r.redirectToAuthorization(cx)
			}
			cx.Set(userContextName, user)

			// step: skip if we are running skip-token-verification
			if r.config.SkipTokenVerification {
				r.log.Warn("skip token verification enabled, skipping verification - TESTING ONLY")
				if user.isExpired() {
					r.log.Error("the session has expired and verification switch off",
						zap.String("client_ip", clientIP),
						zap.String("username", user.name),
						zap.String("expired_on", user.expiresAt.String()))
					return r.redirectToAuthorization(cx)
				}
			} else {
				if err := verifyToken(r.client, user.token); err != nil {
					// step: if the error post verification is anything other than a token
					// expired error we immediately throw an access forbidden - as there is
					// something messed up in the token
					if err != ErrAccessTokenExpired {
						r.log.Error("access token failed verification",
							zap.String("client_ip", clientIP),
							zap.Error(err))
						return r.accessForbidden(cx)
					}

					// step: check if we are refreshing the access tokens and if not re-auth
					if !r.config.EnableRefreshTokens {
						r.log.Error("session expired and access token refreshing is disabled",
							zap.String("client_ip", clientIP),
							zap.String("email", user.name),
							zap.String("expired_on", user.expiresAt.String()))
						return r.redirectToAuthorization(cx)
					}

					r.log.Info("accces token for user has expired, attemping to refresh the token",
						zap.String("client_ip", clientIP),
						zap.String("email", user.email))

					// step: check if the user has refresh token
					refresh, encrypted, err := r.retrieveRefreshToken(cx.Request(), user)
					if err != nil {
						r.log.Error("unable to find a refresh token for user",
							zap.String("client_ip", clientIP),
							zap.String("email", user.email),
							zap.Error(err))
						return r.redirectToAuthorization(cx)
					}

					// attempt to refresh the access token
					token, exp, err := getRefreshedToken(r.client, refresh)
					if err != nil {
						switch err {
						case ErrRefreshTokenExpired:
							r.log.Warn("refresh token has expired, cannot retrieve access token",
								zap.String("client_ip", clientIP),
								zap.String("email", user.email))

							r.clearAllCookies(cx.Request(), cx.Response().Writer)
						default:
							r.log.Error("failed to refresh the access token", zap.Error(err))
						}
						return r.redirectToAuthorization(cx)
					}
					// get the expiration of the new access token
					expiresIn := r.getAccessCookieExpiration(token, refresh)

					r.log.Info("injecting the refreshed access token cookie",
						zap.String("client_ip", clientIP),
						zap.String("cookie_name", r.config.CookieAccessName),
						zap.String("email", user.email),
						zap.Duration("expires_in", time.Until(exp)))

					accessToken := token.Encode()
					if r.config.EnableEncryptedToken {
						if accessToken, err = encodeText(accessToken, r.config.EncryptionKey); err != nil {
							r.log.Error("unable to encode the access token", zap.Error(err))
							return cx.NoContent(http.StatusInternalServerError)
						}
					}
					// step: inject the refreshed access token
					r.dropAccessTokenCookie(cx.Request(), cx.Response().Writer, accessToken, expiresIn)

					if r.useStore() {
						go func(old, new jose.JWT, encrypted string) {
							if err := r.DeleteRefreshToken(old); err != nil {
								r.log.Error("failed to remove old token", zap.Error(err))
							}
							if err := r.StoreRefreshToken(new, encrypted); err != nil {
								r.log.Error("failed to store refresh token", zap.Error(err))
								return
							}
						}(user.token, token, encrypted)
					}
					// update the with the new access token and inject into the context
					user.token = token
					cx.Set(userContextName, user)
				}
			}
			return next(cx)
		}
	}
}

// admissionMiddleware is responsible checking the access token against the protected resource
func (r *oauthProxy) admissionMiddleware(resource *Resource) echo.MiddlewareFunc {
	claimMatches := make(map[string]*regexp.Regexp)
	for k, v := range r.config.MatchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			if found := cx.Get(revokeContextName); found != nil {
				return nil
			}
			user := cx.Get(userContextName).(*userContext)

			// step: we need to check the roles
			if roles := len(resource.Roles); roles > 0 {
				if !hasRoles(resource.Roles, user.roles) {
					r.log.Warn("access denied, invalid roles",
						zap.String("access", "denied"),
						zap.String("email", user.email),
						zap.String("resource", resource.URL),
						zap.String("required", resource.getRoles()))

					return r.accessForbidden(cx)
				}
			}

			// step: if we have any claim matching, lets validate the tokens has the claims
			for claimName, match := range claimMatches {
				// step: if the claim is NOT in the token, we access deny
				value, found, err := user.claims.StringClaim(claimName)
				if err != nil {
					r.log.Error("unable to extract the claim from token",
						zap.String("access", "denied"),
						zap.String("email", user.email),
						zap.String("resource", resource.URL),
						zap.Error(err))

					return r.accessForbidden(cx)
				}

				if !found {
					r.log.Warn("the token does not have the claim",
						zap.String("access", "denied"),
						zap.String("claim", claimName),
						zap.String("email", user.email),
						zap.String("resource", resource.URL))

					return r.accessForbidden(cx)
				}

				// step: check the claim is the same
				if !match.MatchString(value) {
					r.log.Warn("the token claims does not match claim requirement",
						zap.String("access", "denied"),
						zap.String("claim", claimName),
						zap.String("email", user.email),
						zap.String("issued", value),
						zap.String("required", match.String()),
						zap.String("resource", resource.URL))

					return r.accessForbidden(cx)
				}
			}

			r.log.Debug("access permitted to resource",
				zap.String("access", "permitted"),
				zap.String("email", user.email),
				zap.Duration("expires", time.Until(user.expiresAt)),
				zap.String("resource", resource.URL))

			return next(cx)
		}
	}
}

// headersMiddleware is responsible for add the authentication headers for the upstream
func (r *oauthProxy) headersMiddleware(custom []string) echo.MiddlewareFunc {
	customClaims := make(map[string]string)
	for _, x := range custom {
		customClaims[x] = fmt.Sprintf("X-Auth-%s", toHeader(x))
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			if user := cx.Get(userContextName); user != nil {
				id := user.(*userContext)
				cx.Request().Header.Set("X-Auth-Email", id.email)
				cx.Request().Header.Set("X-Auth-ExpiresIn", id.expiresAt.String())
				cx.Request().Header.Set("X-Auth-Roles", strings.Join(id.roles, ","))
				cx.Request().Header.Set("X-Auth-Subject", id.id)
				cx.Request().Header.Set("X-Auth-Token", id.token.Encode())
				cx.Request().Header.Set("X-Auth-Userid", id.name)
				cx.Request().Header.Set("X-Auth-Username", id.name)

				// step: add the authorization header if requested
				if r.config.EnableAuthorizationHeader {
					cx.Request().Header.Set("Authorization", fmt.Sprintf("Bearer %s", id.token.Encode()))
				}
				// step: inject any custom claims
				for claim, header := range customClaims {
					if claim, found := id.claims[claim]; found {
						cx.Request().Header.Set(header, fmt.Sprintf("%v", claim))
					}
				}
			}
			return next(cx)
		}
	}
}

// securityMiddleware performs numerous security checks on the request
func (r *oauthProxy) securityMiddleware() echo.MiddlewareFunc {
	r.log.Info("enabling the security filter middleware")
	secure := secure.New(secure.Options{
		AllowedHosts:          r.config.Hostnames,
		BrowserXssFilter:      r.config.EnableBrowserXSSFilter,
		ContentSecurityPolicy: r.config.ContentSecurityPolicy,
		ContentTypeNosniff:    r.config.EnableContentNoSniff,
		FrameDeny:             r.config.EnableFrameDeny,
		SSLRedirect:           r.config.EnableHTTPSRedirect,
	})

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(cx echo.Context) error {
			if err := secure.Process(cx.Response().Writer, cx.Request()); err != nil {
				r.log.Error("failed security middleware", zap.Error(err))
				return r.accessForbidden(cx)
			}
			return next(cx)
		}
	}
}

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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	uuid "github.com/gofrs/uuid"

	"github.com/PuerkitoBio/purell"
	"github.com/coreos/go-oidc/jose"
	"github.com/go-chi/chi/middleware"
	"github.com/unrolled/secure"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// normalizeFlags is the options to purell
	normalizeFlags purell.NormalizationFlags = purell.FlagRemoveDotSegments | purell.FlagRemoveDuplicateSlashes
)

var gzPool = sync.Pool{
	New: func() interface{} {
		w := gzip.NewWriter(ioutil.Discard)
		return w
	},
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// gzipMiddleware is responsible for compressing a response
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, req)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")

		gz := gzPool.Get().(*gzip.Writer)
		defer gzPool.Put(gz)

		gz.Reset(w)
		defer gz.Close()

		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, req)
	})
}

// entrypointMiddleware is custom filtering for incoming requests
func entrypointMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// @step: create a context for the request
		scope := &RequestScope{}
		// Save the exact formatting of the incoming request so we can use it later
		scope.Path = req.URL.Path
		scope.RawPath = req.URL.RawPath

		// We want to Normalize the URL so that we can more easily and accurately
		// parse it to apply resource protection rules.
		purell.NormalizeURL(req.URL, normalizeFlags)

		// ensure we have a slash in the url
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}
		req.URL.RawPath = req.URL.EscapedPath()

		resp := middleware.NewWrapResponseWriter(w, 1)
		start := time.Now()
		// All the processing, including forwarding the request upstream and getting the response,
		// happens here in this chain.
		next.ServeHTTP(resp, req.WithContext(context.WithValue(req.Context(), contextScopeName, scope)))

		// @metric record the time taken then response code
		latencyMetric.Observe(time.Since(start).Seconds())
		statusMetric.WithLabelValues(fmt.Sprintf("%d", resp.Status()), req.Method).Inc()

		// place back the original uri for any later consumers
		req.URL.Path = scope.Path
		req.URL.RawPath = scope.RawPath
	})
}

// requestIDMiddleware is responsible for adding a request id if none found
func (r *oauthProxy) requestIDMiddleware(header string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if v := req.Header.Get(header); v == "" {
				uuid, err := uuid.NewV1()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				req.Header.Set(header, uuid.String())
			}

			next.ServeHTTP(w, req)
		})
	}
}

// loggingMiddleware is a custom http logger
func (r *oauthProxy) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		resp := w.(middleware.WrapResponseWriter)
		next.ServeHTTP(resp, req)
		addr := req.RemoteAddr
		if req.URL.Path == req.URL.RawPath || req.URL.RawPath == "" {
			r.log.Info("client request",
				zap.Duration("latency", time.Since(start)),
				zap.Int("status", resp.Status()),
				zap.Int("bytes", resp.BytesWritten()),
				zap.String("client_ip", addr),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path))
		} else {
			r.log.Info("client request",
				zap.Duration("latency", time.Since(start)),
				zap.Int("status", resp.Status()),
				zap.Int("bytes", resp.BytesWritten()),
				zap.String("client_ip", addr),
				zap.String("method", req.Method),
				zap.String("path", req.URL.Path),
				zap.String("raw path", req.URL.RawPath))
		}
	})
}

// authenticationMiddleware is responsible for verifying the access token
func (r *oauthProxy) authenticationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			clientIP := req.RemoteAddr
			// grab the user identity from the request
			user, err := r.getIdentity(req)
			if err != nil {
				r.log.Error("no session found in request, redirecting for authorization", zap.Error(err))
				next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
				return
			}
			// create the request scope
			scope := req.Context().Value(contextScopeName).(*RequestScope)
			scope.Identity = user
			ctx := context.WithValue(req.Context(), contextScopeName, scope)

			// step: skip if we are running skip-token-verification
			if r.config.SkipTokenVerification {
				r.log.Warn("skip token verification enabled, skipping verification - TESTING ONLY")
				if user.isExpired() {
					r.log.Error("the session has expired and verification switch off",
						zap.String("client_ip", clientIP),
						zap.String("username", user.name),
						zap.String("expired_on", user.expiresAt.String()))

					next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
					return
				}
			} else { //nolint:gocritic
				if err := verifyToken(r.client, user.token); err != nil {
					// step: if the error post verification is anything other than a token
					// expired error we immediately throw an access forbidden - as there is
					// something messed up in the token
					if err != ErrAccessTokenExpired {
						r.log.Error("access token failed verification",
							zap.String("client_ip", clientIP),
							zap.Error(err))

						next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
						return
					}

					// step: check if we are refreshing the access tokens and if not re-auth
					if !r.config.EnableRefreshTokens {
						r.log.Error("session expired and access token refreshing is disabled",
							zap.String("client_ip", clientIP),
							zap.String("email", user.name),
							zap.String("expired_on", user.expiresAt.String()))

						next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
						return
					}

					r.log.Info("accces token for user has expired, attemping to refresh the token",
						zap.String("client_ip", clientIP),
						zap.String("email", user.email))

					// step: check if the user has refresh token
					refresh, _, err := r.retrieveRefreshToken(req.WithContext(ctx), user)
					if err != nil {
						r.log.Error("unable to find a refresh token for user",
							zap.String("client_ip", clientIP),
							zap.String("email", user.email),
							zap.Error(err))

						next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))
						return
					}

					// attempt to refresh the access token, possibly with a renewed refresh token
					//
					// NOTE: atm, this does not retrieve explicit refresh token expiry from oauth2,
					// and take identity expiry instead: with keycloak, they are the same and equal to
					// "SSO session idle" keycloak setting.
					//
					// exp: expiration of the access token
					// expiresIn: expiration of the ID token
					conf := r.newOAuth2Config(r.config.RedirectionURL)
					token, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := getRefreshedToken(conf, refresh)
					if err != nil {
						switch err {
						case ErrRefreshTokenExpired:
							r.log.Warn("refresh token has expired, cannot retrieve access token",
								zap.String("client_ip", clientIP),
								zap.String("email", user.email))

							r.clearAllCookies(req.WithContext(ctx), w)
						default:
							r.log.Error("failed to refresh the access token", zap.Error(err))
						}
						next.ServeHTTP(w, req.WithContext(r.redirectToAuthorization(w, req)))

						return
					}

					accessExpiresIn := time.Until(accessExpiresAt)

					// get the expiration of the new refresh token
					if newRefreshToken != "" {
						refresh = newRefreshToken
					}
					if refreshExpiresIn == 0 {
						// refresh token expiry claims not available: try to parse refresh token
						refreshExpiresIn = r.getAccessCookieExpiration(refresh)
					}

					r.log.Info("injecting the refreshed access token cookie",
						zap.String("client_ip", clientIP),
						zap.String("cookie_name", r.config.CookieAccessName),
						zap.String("email", user.email),
						zap.Duration("refresh_expires_in", refreshExpiresIn),
						zap.Duration("expires_in", accessExpiresIn))

					accessToken := token.Encode()
					if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
						if accessToken, err = encodeText(accessToken, r.config.EncryptionKey); err != nil {
							r.log.Error("unable to encode the access token", zap.Error(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
					}
					// step: inject the refreshed access token
					r.dropAccessTokenCookie(req.WithContext(ctx), w, accessToken, accessExpiresIn)

					// step: inject the renewed refresh token
					if newRefreshToken != "" {
						r.log.Debug("renew refresh cookie with new refresh token",
							zap.Duration("refresh_expires_in", refreshExpiresIn))
						encryptedRefreshToken, err := encodeText(newRefreshToken, r.config.EncryptionKey)
						if err != nil {
							r.log.Error("failed to encrypt the refresh token", zap.Error(err))
							w.WriteHeader(http.StatusInternalServerError)
							return
						}

						if r.useStore() {
							go func(old, new jose.JWT, encrypted string) {
								if err := r.DeleteRefreshToken(old); err != nil {
									r.log.Error("failed to remove old token", zap.Error(err))
								}
								if err := r.StoreRefreshToken(new, encrypted, refreshExpiresIn); err != nil {
									r.log.Error("failed to store refresh token", zap.Error(err))
									return
								}
							}(user.token, token, encryptedRefreshToken)
						} else {
							r.dropRefreshTokenCookie(req.WithContext(ctx), w, encryptedRefreshToken, refreshExpiresIn)
						}
					}

					// update the with the new access token and inject into the context
					user.token = token
					ctx = context.WithValue(req.Context(), contextScopeName, scope)
				}
			}

			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

// checkClaim checks whether claim in userContext matches claimName, match. It can be String or Strings claim.
func (r *oauthProxy) checkClaim(user *userContext, claimName string, match *regexp.Regexp, resourceURL string) bool {
	errFields := []zapcore.Field{
		zap.String("claim", claimName),
		zap.String("access", "denied"),
		zap.String("email", user.email),
		zap.String("resource", resourceURL),
	}

	if _, found := user.claims[claimName]; !found {
		r.log.Warn("the token does not have the claim", errFields...)
		return false
	}

	// Check string claim.
	valueStr, foundStr, errStr := user.claims.StringClaim(claimName)
	// We have found string claim, so let's check whether it matches.
	if foundStr {
		if match.MatchString(valueStr) {
			return true
		}
		r.log.Warn("claim requirement does not match claim in token", append(errFields,
			zap.String("issued", valueStr),
			zap.String("required", match.String()),
		)...)

		return false
	}

	// Check strings claim.
	valueStrs, foundStrs, errStrs := user.claims.StringsClaim(claimName)
	// We have found strings claim, so let's check whether it matches.
	if foundStrs {
		for _, value := range valueStrs {
			if match.MatchString(value) {
				return true
			}
		}
		r.log.Warn("claim requirement does not match any element claim group in token", append(errFields,
			zap.String("issued", fmt.Sprintf("%v", valueStrs)),
			zap.String("required", match.String()),
		)...)

		return false
	}

	// If this fails, the claim is probably float or int.
	if errStr != nil && errStrs != nil {
		r.log.Error("unable to extract the claim from token (tried string and strings)", append(errFields,
			zap.Error(errStr),
			zap.Error(errStrs),
		)...)
		return false
	}

	r.log.Warn("unexpected error", errFields...)
	return false
}

// admissionMiddleware is responsible checking the access token against the protected resource
func (r *oauthProxy) admissionMiddleware(resource *Resource) func(http.Handler) http.Handler {
	claimMatches := make(map[string]*regexp.Regexp)
	for k, v := range r.config.MatchClaims {
		claimMatches[k] = regexp.MustCompile(v)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// we don't need to continue is a decision has been made
			scope := req.Context().Value(contextScopeName).(*RequestScope)
			if scope.AccessDenied {
				next.ServeHTTP(w, req)
				return
			}
			user := scope.Identity

			// @step: we need to check the roles
			if !hasAccess(resource.Roles, user.roles, !resource.RequireAnyRole) {
				r.log.Warn("access denied, invalid roles",
					zap.String("access", "denied"),
					zap.String("email", user.email),
					zap.String("resource", resource.URL),
					zap.String("roles", resource.getRoles()))

				next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
				return
			}

			// @step: check if we have any groups, the groups are there
			if !hasAccess(resource.Groups, user.groups, false) {
				r.log.Warn("access denied, invalid groups",
					zap.String("access", "denied"),
					zap.String("email", user.email),
					zap.String("resource", resource.URL),
					zap.String("groups", strings.Join(resource.Groups, ",")))

				next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
				return
			}

			// step: if we have any claim matching, lets validate the tokens has the claims
			for claimName, match := range claimMatches {
				if !r.checkClaim(user, claimName, match, resource.URL) {
					next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
					return
				}
			}

			r.log.Debug("access permitted to resource",
				zap.String("access", "permitted"),
				zap.String("email", user.email),
				zap.Duration("expires", time.Until(user.expiresAt)),
				zap.String("resource", resource.URL))

			next.ServeHTTP(w, req)
		})
	}
}

// responseHeaderMiddleware is responsible for adding response headers
func (r *oauthProxy) responseHeaderMiddleware(headers map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// @step: inject any custom response headers
			for k, v := range headers {
				w.Header().Set(k, v)
			}

			next.ServeHTTP(w, req)
		})
	}
}

// identityHeadersMiddleware is responsible for add the authentication headers for the upstream
func (r *oauthProxy) identityHeadersMiddleware(custom []string) func(http.Handler) http.Handler {
	customClaims := make(map[string]string)

	const minSliceLength int = 1

	for _, x := range custom {
		xslices := strings.Split(x, "|")
		x = xslices[0]

		if len(xslices) > minSliceLength {
			customClaims[x] = toHeader(xslices[1])
		} else {
			customClaims[x] = fmt.Sprintf("X-Auth-%s", toHeader(x))
		}
	}

	cookieFilter := []string{r.config.CookieAccessName, r.config.CookieRefreshName}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			scope := req.Context().Value(contextScopeName).(*RequestScope)
			if scope.Identity != nil {
				user := scope.Identity
				req.Header.Set("X-Auth-Audience", strings.Join(user.audiences, ","))
				req.Header.Set("X-Auth-Email", user.email)
				req.Header.Set("X-Auth-ExpiresIn", user.expiresAt.String())
				req.Header.Set("X-Auth-Groups", strings.Join(user.groups, ","))
				req.Header.Set("X-Auth-Roles", strings.Join(user.roles, ","))
				req.Header.Set("X-Auth-Subject", user.id)
				req.Header.Set("X-Auth-Userid", user.name)
				req.Header.Set("X-Auth-Username", user.name)

				// should we add the token header?
				if r.config.EnableTokenHeader {
					req.Header.Set("X-Auth-Token", user.token.Encode())
				}
				// add the authorization header if requested
				if r.config.EnableAuthorizationHeader {
					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", user.token.Encode()))
				}
				// are we filtering out the cookies
				if !r.config.EnableAuthorizationCookies {
					_ = filterCookies(req, cookieFilter)
				}
				// inject any custom claims
				for claim, header := range customClaims {
					if claim, found := user.claims[claim]; found {
						req.Header.Set(header, fmt.Sprintf("%v", claim))
					}
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// securityMiddleware performs numerous security checks on the request
func (r *oauthProxy) securityMiddleware(next http.Handler) http.Handler {
	r.log.Info("enabling the security filter middleware")
	secure := secure.New(secure.Options{
		AllowedHosts:          r.config.Hostnames,
		BrowserXssFilter:      r.config.EnableBrowserXSSFilter,
		ContentSecurityPolicy: r.config.ContentSecurityPolicy,
		ContentTypeNosniff:    r.config.EnableContentNoSniff,
		FrameDeny:             r.config.EnableFrameDeny,
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		SSLRedirect:           r.config.EnableHTTPSRedirect,
	})

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := secure.Process(w, req); err != nil {
			r.log.Warn("failed security middleware", zap.Error(err))
			next.ServeHTTP(w, req.WithContext(r.accessForbidden(w, req)))
			return
		}

		next.ServeHTTP(w, req)
	})
}

// proxyDenyMiddleware just block everything
func proxyDenyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sc := req.Context().Value(contextScopeName)
		var scope *RequestScope
		if sc == nil {
			scope = &RequestScope{}
		} else {
			scope = sc.(*RequestScope)
		}
		scope.AccessDenied = true
		// update the request context
		ctx := context.WithValue(req.Context(), contextScopeName, scope)

		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

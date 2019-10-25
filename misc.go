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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/jose"
	"go.uber.org/zap"
)

// revokeProxy is responsible to stopping the middleware from proxying the request
func (r *oauthProxy) revokeProxy(w http.ResponseWriter, req *http.Request) context.Context {
	var scope *RequestScope
	sc := req.Context().Value(contextScopeName)
	switch sc {
	case nil:
		scope = &RequestScope{AccessDenied: true}
	default:
		scope = sc.(*RequestScope)
	}
	scope.AccessDenied = true

	return context.WithValue(req.Context(), contextScopeName, scope)
}

// redirectToURL redirects the user and aborts the context
func (r *oauthProxy) redirectToURL(url string, w http.ResponseWriter, req *http.Request, statusCode int) context.Context {
	r.log.Debug("redirecting to", zap.String("location", url))
	w.Header().Add("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	http.Redirect(w, req, url, statusCode)

	return r.revokeProxy(w, req)
}

// redirectToAuthorization redirects the user to authorization handler
func (r *oauthProxy) redirectToAuthorization(w http.ResponseWriter, req *http.Request) context.Context {
	if r.config.NoRedirects {
		r.errorResponse(w, req, "", http.StatusUnauthorized, nil)
		return r.revokeProxy(w, req)
	}

	// step: add a state referrer to the authorization page
	uuid := r.writeStateParameterCookie(req, w)
	authQuery := fmt.Sprintf("?state=%s", uuid)

	// step: if verification is switched off, we can't authorize
	if r.config.SkipTokenVerification {
		r.errorResponse(w, req, "refusing to redirect to authorization endpoint, skip token verification switched on", http.StatusForbidden, nil)
		return r.revokeProxy(w, req)
	}
	if r.config.InvalidAuthRedirectsWith303 {
		r.redirectToURL(r.config.WithOAuthURI(authorizationURL+authQuery), w, req, http.StatusSeeOther)
	} else {
		r.redirectToURL(r.config.WithOAuthURI(authorizationURL+authQuery), w, req, http.StatusTemporaryRedirect)
	}

	return r.revokeProxy(w, req)
}

// getAccessCookieExpiration calculates the expiration of the access token cookie
func (r *oauthProxy) getAccessCookieExpiration(token jose.JWT, refresh string) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := r.config.AccessTokenDuration
	if _, ident, err := parseToken(refresh); err == nil {
		delta := time.Until(ident.ExpiresAt)
		if delta > 0 {
			duration = delta
		}
		r.log.Debug("parsed refresh token with new duration", zap.Duration("new duration", delta))
	} else {
		r.log.Debug("refresh token is opaque and cannot be used to derive calculated duration")
	}

	return duration
}

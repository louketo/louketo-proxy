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
	"encoding/base64"
	"fmt"
	"net/http"
	"path"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/labstack/echo"
)

// revokeProxy is responsible to stopping the middleware from proxying the request
func (r *oauthProxy) revokeProxy(cx echo.Context) {
	cx.Set(revokeContextName, true)
}

// accessForbidden redirects the user to the forbidden page
func (r *oauthProxy) accessForbidden(cx echo.Context) error {
	r.revokeProxy(cx)

	if r.config.hasCustomForbiddenPage() {
		tplName := path.Base(r.config.ForbiddenPage)
		err := cx.Render(http.StatusForbidden, tplName, r.config.Tags)
		if err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"template": tplName,
			}).Error("unable to render the template")
		}

		return err
	}

	return cx.NoContent(http.StatusForbidden)
}

// redirectToURL redirects the user and aborts the context
func (r *oauthProxy) redirectToURL(url string, cx echo.Context) error {
	r.revokeProxy(cx)

	return cx.Redirect(http.StatusTemporaryRedirect, url)
}

// redirectToAuthorization redirects the user to authorization handler
func (r *oauthProxy) redirectToAuthorization(cx echo.Context) error {
	r.revokeProxy(cx)

	if r.config.NoRedirects {
		return cx.NoContent(http.StatusUnauthorized)
	}
	// step: add a state referrer to the authorization page
	authQuery := fmt.Sprintf("?state=%s", base64.StdEncoding.EncodeToString([]byte(cx.Request().URL.RequestURI())))

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		log.Errorf("refusing to redirection to authorization endpoint, skip token verification switched on")
		return cx.NoContent(http.StatusForbidden)
	}

	return r.redirectToURL(oauthURL+authorizationURL+authQuery, cx)
}

// getAccessCookieExpiration calucates the expiration of the access token cookie
func (r *oauthProxy) getAccessCookieExpiration(token jose.JWT, refresh string) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duraction of the
	// refresh token
	duration := r.config.AccessTokenDuration
	if _, ident, err := parseToken(refresh); err == nil {
		duration = ident.ExpiresAt.Sub(time.Now())
	}

	return duration
}

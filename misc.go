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

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

// accessForbidden redirects the user to the forbidden page
func (r *oauthProxy) accessForbidden(cx *gin.Context) {
	if r.config.hasCustomForbiddenPage() {
		cx.HTML(http.StatusForbidden, path.Base(r.config.ForbiddenPage), r.config.Tags)
		cx.Abort()
		return
	}

	cx.AbortWithStatus(http.StatusForbidden)
}

// redirectToURL redirects the user and aborts the context
func (r *oauthProxy) redirectToURL(url string, cx *gin.Context) {
	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
}

// redirectToAuthorization redirects the user to authorization handler
func (r *oauthProxy) redirectToAuthorization(cx *gin.Context) {
	if r.config.NoRedirects {
		cx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// step: add a state referrer to the authorization page
	authQuery := fmt.Sprintf("?state=%s", base64.StdEncoding.EncodeToString([]byte(cx.Request.URL.RequestURI())))

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		log.Errorf("refusing to redirection to authorization endpoint, skip token verification switched on")

		cx.AbortWithStatus(http.StatusForbidden)
		return
	}

	r.redirectToURL(oauthURL+authorizationURL+authQuery, cx)
}

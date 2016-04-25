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
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"github.com/unrolled/secure"
)

//
// loggingHandler is a custom http logger
//
func (r *oauthProxy) loggingHandler() gin.HandlerFunc {
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
func (r *oauthProxy) securityHandler() gin.HandlerFunc {
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
// crossSiteHandler injects the CORS headers, if set, for request made to /oauth
//
func (r *oauthProxy) crossSiteHandler() gin.HandlerFunc {
	return func(cx *gin.Context) {
		c := r.config.CORS
		if len(c.Origins) > 0 {
			cx.Writer.Header().Set("Access-Control-Allow-Origin", strings.Join(c.Origins, ","))
		}
		if len(c.Methods) > 0 {
			cx.Writer.Header().Set("Access-Control-Allow-Methods", strings.Join(c.Methods, ","))
		}
		if len(c.Headers) > 0 {
			cx.Writer.Header().Set("Access-Control-Allow-Headers", strings.Join(c.Headers, ","))
		}
		if len(c.ExposedHeaders) > 0 {
			cx.Writer.Header().Set("Access-Control-Expose-Headers", strings.Join(c.ExposedHeaders, ","))
		}
		if c.Credentials {
			cx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if c.MaxAge > 0 {
			cx.Writer.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", int(c.MaxAge.Seconds())))
		}
	}
}

//
// proxyHandler is responsible to proxy the requests on to the upstream endpoint
//
func (r *oauthProxy) proxyHandler(cx *gin.Context) {
	// step: double check, if enforce is true and no user context it's a internal error
	if _, found := cx.Get(cxEnforce); found {
		if _, found := cx.Get(userContextName); !found {
			log.Errorf("no user context found for a secure request")
			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	// step: retrieve the user context if any
	if user, found := cx.Get(userContextName); found {
		id := user.(*userContext)
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
		if err := tryUpdateConnection(cx, r.endpoint); err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Errorf("failed to upgrade the connection")

			cx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		cx.Abort()

		return
	}

	r.upstream.ServeHTTP(cx.Writer, cx.Request)
}

//
// expirationHandler checks if the token has expired
//
func (r *oauthProxy) expirationHandler(cx *gin.Context) {
	// step: get the access token from the request
	user, err := getIdentity(cx)
	if err != nil {
		cx.AbortWithError(http.StatusUnauthorized, err)
		return
	}
	// step: check the access is not expired
	if user.isExpired() {
		cx.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	cx.AbortWithStatus(http.StatusOK)
}

//
// tokenHandler display access token to screen
//
func (r *oauthProxy) tokenHandler(cx *gin.Context) {
	// step: extract the access token from the request
	user, err := getIdentity(cx)
	if err != nil {
		cx.AbortWithError(http.StatusBadRequest, fmt.Errorf("unable to retrieve session, error: %s", err))
		return
	}

	// step: write the json content
	cx.Writer.Header().Set("Content-Type", "application/json")
	cx.String(http.StatusOK, fmt.Sprintf("%s", user.token.Payload))
}

//
// healthHandler is a health check handler for the service
//
func (r *oauthProxy) healthHandler(cx *gin.Context) {
	cx.String(http.StatusOK, "OK")
}

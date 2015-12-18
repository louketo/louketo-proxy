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
	"net/url"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

// NewProxy create's a new keycloak proxy from configuration
func NewProxy(cfg *Config) (*KeycloakProxy, error) {
	upstreamURL, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	// step: initialize the reverse http proxy
	reverse, err := initializeReverseProxy(upstreamURL)
	if err != nil {
		return nil, err
	}

	// step: initialize the openid client
	client, clientCfg, err := initializeOpenID(cfg.DiscoveryURL,
		cfg.ClientID, cfg.Secret, cfg.RedirectionURL, cfg.Scopes)
	if err != nil {
		return nil, err
	}

	// step: create a proxy service
	service := &KeycloakProxy{
		openIDConfig: clientCfg,
		openIDClient: client,
		config:       cfg,
		proxy:        reverse,
		upstreamURL:  upstreamURL,
	}

	// step: initialize the gin router
	glog.V(3).Infof("initializing the http router, listening: %s", cfg.Listen)

	service.router = gin.Default()
	for _, resource := range cfg.Resources {
		glog.Infof("protecting resources under: %s", resource)
	}
	service.router.Use(service.entrypointHandler(), service.authenticationHandler(), service.admissionHandler())

	// step: add the oauth handlers and health
	service.router.GET(authorizationURL, service.authorizationHandler)
	service.router.GET(callbackURL, service.callbackHandler)
	service.router.GET(signInPageURL, service.signInHandler)
	service.router.GET(accessForbiddenPageURL, service.forbiddenAccessHandler)
	service.router.GET(healthURL, service.healthHandler)
	service.router.Use(service.proxyHandler)

	return service, nil
}

// Run starts the proxy service
func (r *KeycloakProxy) Run() error {
	go func() {
		var err error
		if r.config.TLSCertificate == "" {
			err = r.router.Run(r.config.Listen)
		} else {
			err = r.router.RunTLS(r.config.Listen, r.config.TLSCertificate, r.config.TLSPrivateKey)
		}
		if err != nil {
			glog.Fatalf("failed to start the service, error: %s", err)
		}
	}()

	return nil
}

// redirectToURL redirects the user and aborts the context
func (r KeycloakProxy) redirectToURL(url string, cx *gin.Context) {
	glog.Infof("redirecting the client to: %s", url)
	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
}

// accessForbidden redirects the user to the forbidden page
func (r KeycloakProxy) accessForbidden(cx *gin.Context) {
	if r.config.AccessForbiddenPage != "" {
		r.redirectToURL(accessForbiddenPageURL, cx)
		return
	}

	cx.AbortWithStatus(http.StatusForbidden)
}

// redirectToAuthorization redirects the user to authorization handler
func (r KeycloakProxy) redirectToAuthorization(cx *gin.Context) {
	// step: add a state referrer to the authorization page
	authQuery := fmt.Sprintf("?state=%s", cx.Request.URL.String())

	if r.config.SignInPage != "" {
		r.redirectToURL(signInPageURL+authQuery, cx)
		return
	}

	r.redirectToURL(authorizationURL+authQuery, cx)
}

// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
func (r *KeycloakProxy) tryUpdateConnection(cx *gin.Context) error {
	// step: dial the endpoint
	tlsConn, err := tryDialEndpoint(r.upstreamURL)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := cx.Writer.(http.Hijacker).Hijack()
	if err != nil {

	}
	defer clientConn.Close()

	// step: write the request to upstream
	if err = cx.Request.Write(tlsConn); err != nil {
		return err
	}

	// step: copy the date between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go transferBytes(tlsConn, clientConn, &wg)
	go transferBytes(clientConn, tlsConn, &wg)
	wg.Wait()

	return nil
}

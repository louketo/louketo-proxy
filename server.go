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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

// keycloakProxy is the server component
type keycloakProxy struct {
	config *Config
	// the gin service
	router *gin.Engine
	// the oidc client
	openIDClient *oidc.Client
	// the proxy client
	proxy reverseProxy
	// the upstream endpoint
	upstreamURL *url.URL
}

type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

func init() {
	// step: ensure all time is in UTC
	time.LoadLocation("UTC")
}

// newKeycloakProxy create's a new keycloak proxy from configuration
func newKeycloakProxy(cfg *Config) (*keycloakProxy, error) {
	// step: set the logging level
	if cfg.LogJSONFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("starting %s, version: %s, author: %s", prog, version, author)

	// step: parse the upstream endpoint
	upstreamURL, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	// step: create a proxy service
	service := &keycloakProxy{
		config:      cfg,
		upstreamURL: upstreamURL,
	}

	// step: initialize the reverse http proxy
	reverse, err := service.initializeReverseProxy(upstreamURL)
	if err != nil {
		return nil, err
	}
	service.proxy = reverse

	// step: initialize the openid client
	if cfg.SkipTokenVerification {
		log.Infof("TESTING ONLY CONFIG - the verification of the token have been disabled")

	} else {
		client, err := initializeOpenID(cfg.DiscoveryURL, cfg.ClientID, cfg.Secret, cfg.RedirectionURL, cfg.Scopes)
		if err != nil {
			return nil, err
		}
		service.openIDClient = client
	}

	// step: initialize the gin router
	router := gin.New()
	service.router = router

	// step: load the templates
	service.initializeTemplates()
	for _, resource := range cfg.Resources {
		log.Infof("protecting resources under uri: %s", resource)
	}
	for name, value := range cfg.ClaimsMatch {
		log.Infof("the token must container the claim: %s, required: %s", name, value)
	}

	service.initializeRouter()

	return service, nil
}

// initializeRouter sets up the gin routing
func (r keycloakProxy) initializeRouter() {
	r.router.Use(gin.Recovery())
	// step: are we logging the traffic?
	if r.config.LogRequests {
		r.router.Use(r.loggingHandler())
	}
	// step: enabling the security filter?
	if r.config.EnableSecurityFilter {
		log.Infof("enabling the security handler")
		r.router.Use(r.securityHandler())
	}

	// step: add the routing
	r.router.GET(authorizationURL, r.oauthAuthorizationHandler)
	r.router.GET(callbackURL, r.oauthCallbackHandler)
	r.router.GET(healthURL, r.healthHandler)
	r.router.GET(tokenURL, r.tokenHandler)
	r.router.GET(expiredURL, r.expirationHandler)
	r.router.GET(logoutURL, r.logoutHandler)

	r.router.Use(r.entryPointHandler(), r.authenticationHandler(), r.admissionHandler())
}

// initializeTemplates loads the custom template
func (r *keycloakProxy) initializeTemplates() {
	var list []string

	if r.config.SignInPage != "" {
		log.Debugf("loading the custom sign in page: %s", r.config.SignInPage)
		list = append(list, r.config.SignInPage)
	}
	if r.config.ForbiddenPage != "" {
		log.Debugf("loading the custom sign forbidden page: %s", r.config.ForbiddenPage)
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		log.Infof("loading the custom templates: %s", strings.Join(list, ","))
		r.router.LoadHTMLFiles(list...)
	}
}

// Run starts the proxy service
func (r *keycloakProxy) Run() error {
	tlsConfig := &tls.Config{}

	// step: are we doing mutual tls?
	if r.config.TLSCaCertificate != "" {
		log.Infof("enabling mutual tls, reading in the ca: %s", r.config.TLSCaCertificate)

		caCert, err := ioutil.ReadFile(r.config.TLSCaCertificate)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	go func() {
		log.Infof("keycloak proxy service starting on %s", r.config.Listen)

		var err error
		if r.config.TLSCertificate == "" {
			err = r.router.Run(r.config.Listen)
		} else {
			server := &http.Server{
				Addr:      r.config.Listen,
				Handler:   r.router,
				TLSConfig: tlsConfig,
			}
			err = server.ListenAndServeTLS(r.config.TLSCertificate, r.config.TLSPrivateKey)
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Fatalf("failed to start the service")
		}
	}()

	return nil
}

// redirectToURL redirects the user and aborts the context
func (r keycloakProxy) redirectToURL(url string, cx *gin.Context) {
	// step: add the cors headers
	r.injectCORSHeaders(cx)

	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
}

// accessForbidden redirects the user to the forbidden page
func (r keycloakProxy) accessForbidden(cx *gin.Context) {
	// step: do we have a custom forbidden page
	if r.config.hasForbiddenPage() {
		cx.HTML(http.StatusForbidden, path.Base(r.config.ForbiddenPage), r.config.TagData)
		cx.Abort()
		return
	}

	cx.AbortWithStatus(http.StatusForbidden)
}

// redirectToAuthorization redirects the user to authorization handler
func (r keycloakProxy) redirectToAuthorization(cx *gin.Context) {
	// step: are we handling redirects?
	if r.config.NoRedirects {
		cx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// step: add a state referrer to the authorization page
	authQuery := fmt.Sprintf("?state=%s", cx.Request.URL.String())

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		log.Errorf("refusing to redirection to authorization endpoint, skip token verification switched on")
		cx.AbortWithStatus(http.StatusForbidden)
		return
	}

	r.redirectToURL(authorizationURL+authQuery, cx)
}

// injectCORSHeaders adds the cors access controls to the oauth responses
func (r *keycloakProxy) injectCORSHeaders(cx *gin.Context) {
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

func (r *keycloakProxy) addAuthenticationHeader(cx *gin.Context, errorCode, errorMessage string) {
	// step: inject the error message
	header := "Bearer realm=\"secure\""
	if errorCode != "" {
		header += fmt.Sprintf(",error=\"%s\"", errorCode)
	}
	if errorMessage != "" {
		header += fmt.Sprintf(", error_description=\"%s\"", errorMessage)
	}

	// step: add the www-authenticate header
	cx.Writer.Header().Set("WWW-Authenticate", header)
}

// tryUpdateConnection attempt to upgrade the connection to a http pdy stream
func (r *keycloakProxy) tryUpdateConnection(cx *gin.Context) error {
	// step: dial the endpoint
	tlsConn, err := tryDialEndpoint(r.upstreamURL)
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	// step: we need to hijack the underlining client connection
	clientConn, _, err := cx.Writer.(http.Hijacker).Hijack()
	if err != nil {
		return err
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

// initializeReverseProxy create a reverse http proxy from the upstream
func (r *keycloakProxy) initializeReverseProxy(upstream *url.URL) (reverseProxy, error) {
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	// step: we don't care about the cert verification here
	proxy.Transport = &http.Transport{
		Dial: (&net.Dialer{
			KeepAlive: 10 * time.Second,
			Timeout:   10 * time.Second,
		}).Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: r.config.SkipUpstreamTLSVerify,
		},
		DisableKeepAlives:   !r.config.Keepalives,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return proxy, nil
}

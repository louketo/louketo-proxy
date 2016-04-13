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
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/gin-gonic/gin"
)

type oauthProxy struct {
	// the proxy configuration
	config *Config
	// the gin service
	router *gin.Engine
	// the opened client
	client *oidc.Client
	// the openid provider configuration
	provider oidc.ProviderConfig
	// the proxy client
	upstream reverseProxy
	// the upstream endpoint url
	endpoint *url.URL
	// the store interface
	store Store
}

type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

func init() {
	// step: ensure all time is in UTC
	time.LoadLocation("UTC")
}

//
// newProxy create's a new proxy from configuration
//
func newProxy(cfg *Config) (*oauthProxy, error) {
	var err error
	// step: set the logging level
	if cfg.LogJSONFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if cfg.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("starting %s, version: %s, author: %s", prog, version, author)

	service := &oauthProxy{config: cfg}

	// step: parse the upstream endpoint
	service.endpoint, err = url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	// step: initialize the store if any
	if cfg.StoreURL != "" {
		if service.store, err = newStore(cfg.StoreURL); err != nil {
			return nil, err
		}
	}

	// step: initialize the reverse http proxy
	service.upstream, err = service.setupReverseProxy(service.endpoint)
	if err != nil {
		return nil, err
	}

	// step: initialize the openid client
	if !cfg.SkipTokenVerification {
		service.client, service.provider, err = initializeOpenID(cfg)
		if err != nil {
			return nil, err
		}
	} else {
		log.Infof("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	// step: initialize the gin router
	service.router = gin.New()

	// step: load the templates
	if err = service.setupTemplates(); err != nil {
		return nil, err
	}
	// step: setup the gin router and add router
	if err := service.setupRouter(); err != nil {
		return nil, err
	}
	// step: display the protected resources
	for _, resource := range cfg.Resources {
		log.Infof("protecting resources under uri: %s", resource)
	}
	for name, value := range cfg.ClaimsMatch {
		log.Infof("the token must container the claim: %s, required: %s", name, value)
	}

	return service, nil
}

//
// Run starts the proxy service
//
func (r *oauthProxy) Run() error {
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

//
// redirectToURL redirects the user and aborts the context
//
func (r *oauthProxy) redirectToURL(url string, cx *gin.Context) {
	// step: add the cors headers
	r.injectCORSHeaders(cx)

	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
}

//
// accessForbidden redirects the user to the forbidden page
//
func (r *oauthProxy) accessForbidden(cx *gin.Context) {
	if r.config.hasCustomForbiddenPage() {
		cx.HTML(http.StatusForbidden, path.Base(r.config.ForbiddenPage), r.config.TagData)
		cx.Abort()
		return
	}

	cx.AbortWithStatus(http.StatusForbidden)
}

//
// redirectToAuthorization redirects the user to authorization handler
//
func (r *oauthProxy) redirectToAuthorization(cx *gin.Context) {
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

//
// injectCORSHeaders adds the cors access controls to the oauth responses
//
func (r *oauthProxy) injectCORSHeaders(cx *gin.Context) {
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

//
// setupReverseProxy create a reverse http proxy from the upstream
//
func (r *oauthProxy) setupReverseProxy(upstream *url.URL) (reverseProxy, error) {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
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

//
// setupRouter sets up the gin routing
//
func (r oauthProxy) setupRouter() error {
	r.router.Use(gin.Recovery())
	// step: are we logging the traffic?
	if r.config.LogRequests {
		r.router.Use(r.loggingHandler())
	}
	// step: enabling the security filter?
	if r.config.EnableSecurityFilter {
		r.router.Use(r.securityHandler())
	}
	// step: add the routing
	r.router.GET(authorizationURL, r.oauthAuthorizationHandler)
	r.router.GET(callbackURL, r.oauthCallbackHandler)
	r.router.GET(healthURL, r.healthHandler)
	r.router.GET(tokenURL, r.tokenHandler)
	r.router.GET(expiredURL, r.expirationHandler)
	r.router.GET(logoutURL, r.logoutHandler)
	r.router.POST(loginURL, r.loginHandler)

	r.router.Use(r.entryPointHandler(), r.authenticationHandler(), r.admissionHandler())

	return nil
}

//
// setupTemplates loads the custom template
//
func (r *oauthProxy) setupTemplates() error {
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

	return nil
}

//
// useStore checks if we are using a store to hold the refresh tokens
//
func (r *oauthProxy) useStore() bool {
	return r.store != nil
}

//
// StoreRefreshToken the token to the store
//
func (r *oauthProxy) StoreRefreshToken(token jose.JWT, value string) error {
	return r.store.Set(getHashKey(&token), value)
}

//
// Get retrieves a token from the store, the key we are using here is the access token
//
func (r *oauthProxy) GetRefreshToken(token jose.JWT) (string, error) {
	// step: the key is the access token
	v, err := r.store.Get(getHashKey(&token))
	if err != nil {
		return v, err
	}
	if v == "" {
		return v, ErrNoSessionStateFound
	}

	return v, nil
}

//
// DeleteRefreshToken removes a key from the store
//
func (r *oauthProxy) DeleteRefreshToken(token jose.JWT) error {
	if err := r.store.Delete(getHashKey(&token)); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Errorf("failed to delete the token from store")

		return err
	}

	return nil
}

// Close is used to close off any resources
func (r *oauthProxy) CloseStore() error {
	if r.store != nil {
		return r.store.Close()
	}

	return nil
}

func getHashKey(token *jose.JWT) string {
	hash := md5.Sum([]byte(token.Encode()))
	return hex.EncodeToString(hash[:])
}

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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/armon/go-proxyproto"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/elazarl/goproxy"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	httplog "log"
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
	store storage
	// the prometheus handler
	prometheusHandler http.Handler
	// the http request metrics
	httpMetrics *prometheus.CounterVec
}

type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}

func init() {
	// step: ensure all time is in UTC
	time.LoadLocation("UTC")
	// step: set the core
	runtime.GOMAXPROCS(runtime.NumCPU())
}

//
// newProxy create's a new proxy from configuration
//
func newProxy(config *Config) (*oauthProxy, error) {
	var err error
	// step: set the logging level
	if config.LogJSONFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if config.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	// step: disable the logging for http server - stop us from getting all those
	// annoying EOF from tcp health checks
	httplog.SetOutput(ioutil.Discard)

	log.Infof("starting %s, author: %s, version: %s, ", prog, author, version)

	service := &oauthProxy{
		config:            config,
		prometheusHandler: prometheus.Handler(),
	}

	// step: parse the upstream endpoint
	service.endpoint, err = url.Parse(config.Upstream)
	if err != nil {
		return nil, err
	}

	// step: initialize the store if any
	if config.StoreURL != "" {
		if service.store, err = createStorage(config.StoreURL); err != nil {
			return nil, err
		}
	}

	// step: initialize the openid client
	if !config.SkipTokenVerification {
		service.client, service.provider, err = createOpenIDClient(config)
		if err != nil {
			return nil, err
		}
	} else {
		log.Warnf("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warnf("Note: client credentials are not set, depending on provider (confidential|public) you might be able to auth")
	}

	// step:
	switch config.EnableForwarding {
	case true:
		if err := createForwardingProxy(config, service); err != nil {
			return nil, err
		}
	default:
		if err := createReverseProxy(config, service); err != nil {
			return nil, err
		}
	}

	return service, nil
}

//
// createReverseProxy creates a reverse proxy
//
func createReverseProxy(config *Config, service *oauthProxy) error {
	log.Infof("enabled reverse proxy mode, upstream url: %s", config.Upstream)

	// step: display the protected resources
	for _, resource := range config.Resources {
		log.Infof("protecting resources under uri: %s", resource)
	}
	for name, value := range config.MatchClaims {
		log.Infof("the token must container the claim: %s, required: %s", name, value)
	}

	// step: initialize the reverse http proxy
	if err := service.createUpstreamProxy(service.endpoint); err != nil {
		return err
	}

	// step: setup the gin router and add router
	if err := service.createEndpoints(); err != nil {
		return err
	}

	// step: create the metrics
	if err := service.createMetrics(); err != nil {
		return err
	}

	// step: load the templates
	if err := service.createTemplates(); err != nil {
		return err
	}

	return nil
}

//
// createForwardingProxy creates a forwarding proxy
//
func createForwardingProxy(config *Config, service *oauthProxy) error {
	log.Infof("enabled forward signing proxy mode")

	if config.SkipUpstreamTLSVerify {
		log.Warnf("TLS verification switched off; in forward signing mode it's recommended you verify! (--skip-upstream-tls-verify=false)")
	}

	// step: initialize the reverse http proxy
	if err := service.createUpstreamProxy(nil); err != nil {
		return err
	}

	gin.SetMode(gin.ReleaseMode)
	// step: enable debugging in verbose more
	if config.Verbose {
		gin.SetMode(gin.DebugMode)
	}
	engine := gin.New()

	// step: default to release mode, only go debug on verbose logging
	engine.Use(gin.Recovery())
	service.router = engine

	// step: are we logging the traffic?
	if config.LogRequests {
		engine.Use(service.loggingHandler())
	}

	engine.Use(service.forwardProxyHandler())

	return nil
}

//
// Run starts the proxy service
//
func (r *oauthProxy) Run() (err error) {
	tlsConfig := &tls.Config{}

	// step: are we doing mutual tls?
	if r.config.TLSCaCertificate != "" {
		log.Infof("enabling mutual tls, reading in the signing ca: %s", r.config.TLSCaCertificate)
		caCert, err := ioutil.ReadFile(r.config.TLSCaCertificate)
		if err != nil {
			return err
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	server := &http.Server{
		Addr:    r.config.Listen,
		Handler: r.router,
	}

	// step: create the listener
	var listener net.Listener
	switch strings.HasPrefix(r.config.Listen, "unix://") {
	case true:
		socket := strings.Trim(r.config.Listen, "unix://")
		// step: delete the socket if it exists
		if exists := fileExists(socket); exists {
			if err := os.Remove(socket); err != nil {
				return err
			}
		}

		log.Infof("listening on unix socket: %s", r.config.Listen)
		if listener, err = net.Listen("unix", socket); err != nil {
			return err
		}

	default:
		listener, err = net.Listen("tcp", r.config.Listen)
		if err != nil {
			return err
		}
	}

	// step: configure tls
	if r.config.TLSCertificate != "" && r.config.TLSPrivateKey != "" {
		server.TLSConfig = tlsConfig
		if tlsConfig.NextProtos == nil {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}
		if len(tlsConfig.Certificates) == 0 || r.config.TLSCertificate != "" || r.config.TLSPrivateKey != "" {
			var err error
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			if tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(r.config.TLSCertificate, r.config.TLSPrivateKey); err != nil {
				return err
			}
		}
		log.Infof("tls enabled, certificate: %s, key: %s", r.config.TLSCertificate, r.config.TLSPrivateKey)

		listener = tls.NewListener(listener, tlsConfig)
	}

	// step: wrap the listen in a proxy protocol
	if r.config.EnableProxyProtocol {
		log.Infof("enabling the proxy protocol on listener: %s", r.config.Listen)
		listener = &proxyproto.Listener{listener}
	}

	go func() {
		log.Infof("keycloak proxy service starting on %s", r.config.Listen)
		if err = server.Serve(listener); err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Fatalf("failed to start the service")
		}
	}()

	return nil
}

//
// createUpstreamProxy create a reverse http proxy from the upstream
//
func (r *oauthProxy) createUpstreamProxy(upstream *url.URL) error {
	// step: create the default dialer
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// step: are we using a unix socket?
	if upstream != nil && upstream.Scheme == "unix" {
		log.Infof("using the unix domain socket: %s%s for upstream", upstream.Host, upstream.Path)
		socketPath := fmt.Sprintf("%s%s", upstream.Host, upstream.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		upstream.Path = ""
		upstream.Host = "domain-sock"
		upstream.Scheme = "http"
	}

	// step: create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()
	// step: update the tls configuration of the reverse proxy
	proxy.Tr = &http.Transport{
		Dial: dialer,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: r.config.SkipUpstreamTLSVerify,
		},
		DisableKeepAlives: !r.config.UpstreamKeepalives,
	}
	r.upstream = proxy

	return nil
}

//
// createEndpoints sets up the gin routing
//
func (r *oauthProxy) createEndpoints() error {
	gin.SetMode(gin.ReleaseMode)
	if r.config.Verbose {
		gin.SetMode(gin.DebugMode)
	}
	engine := gin.New()
	engine.Use(gin.Recovery())

	// step: are we logging the traffic?
	if r.config.LogRequests {
		engine.Use(r.loggingHandler())
	}

	// step: enabling the security filter?
	if r.config.EnableSecurityFilter {
		engine.Use(r.securityHandler())
	}

	// step: add the routing
	oauth := engine.Group(oauthURL).Use(r.crossOriginResourceHandler(r.config.CrossOrigin))
	{
		oauth.GET(authorizationURL, r.oauthAuthorizationHandler)
		oauth.GET(callbackURL, r.oauthCallbackHandler)
		oauth.GET(healthURL, r.healthHandler)
		oauth.GET(tokenURL, r.tokenHandler)
		oauth.GET(expiredURL, r.expirationHandler)
		oauth.GET(logoutURL, r.logoutHandler)
		oauth.POST(loginURL, r.loginHandler)
		oauth.GET(metricsURL, r.metricsHandler)
	}

	engine.Use(
		r.entryPointHandler(),
		r.authenticationHandler(),
		r.admissionHandler(),
		r.upstreamHeadersHandler(r.config.AddClaims),
		r.upstreamReverseProxyHandler())

	r.router = engine

	return nil
}

//
// createMetrics creates the prometheus metrics endpoints
//
func (r *oauthProxy) createMetrics() error {
	log.Infof("creating the service metrics, available on %s%s", oauthURL, metricsURL)

	r.httpMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_total",
			Help: "The HTTP requests broken partitioned by status code",
		},
		[]string{"code", "method"},
	)

	// step: register the metric with prometheus
	collector := prometheus.MustRegisterOrGet(r.httpMetrics)
	r.httpMetrics = collector.(*prometheus.CounterVec)

	return nil
}

//
// createTemplates loads the custom template
//
func (r *oauthProxy) createTemplates() error {
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

//
// Close is used to close off any resources
//
func (r *oauthProxy) CloseStore() error {
	if r.store != nil {
		return r.store.Close()
	}

	return nil
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
// redirectToURL redirects the user and aborts the context
//
func (r *oauthProxy) redirectToURL(url string, cx *gin.Context) {
	cx.Redirect(http.StatusTemporaryRedirect, url)
	cx.Abort()
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
	authQuery := fmt.Sprintf("?state=%s", base64.StdEncoding.EncodeToString([]byte(cx.Request.URL.RequestURI())))

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		log.Errorf("refusing to redirection to authorization endpoint, skip token verification switched on")

		cx.AbortWithStatus(http.StatusForbidden)
		return
	}

	r.redirectToURL(oauthURL+authorizationURL+authQuery, cx)
}

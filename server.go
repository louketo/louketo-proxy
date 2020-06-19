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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"

	"golang.org/x/crypto/acme/autocert"

	httplog "log"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/coreos/go-oidc/oidc"
	"github.com/elazarl/goproxy"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

type oauthProxy struct {
	client         *oidc.Client
	config         *Config
	endpoint       *url.URL
	idp            oidc.ProviderConfig
	idpClient      *http.Client
	listener       net.Listener
	log            *zap.Logger
	metricsHandler http.Handler
	router         http.Handler
	server         *http.Server
	store          storage
	templates      *template.Template
	upstream       reverseProxy
}

func init() {
	_, _ = time.LoadLocation("UTC")      // ensure all time is in UTC [NOTE(fredbi): no this does just nothing]
	runtime.GOMAXPROCS(runtime.NumCPU()) // set the core
	prometheus.MustRegister(certificateRotationMetric)
	prometheus.MustRegister(latencyMetric)
	prometheus.MustRegister(oauthLatencyMetric)
	prometheus.MustRegister(oauthTokensMetric)
	prometheus.MustRegister(statusMetric)
}

// newProxy create's a new proxy from configuration
func newProxy(config *Config) (*oauthProxy, error) {
	// create the service logger
	log, err := createLogger(config)
	if err != nil {
		return nil, err
	}

	log.Info("starting the service", zap.String("prog", prog), zap.String("author", author), zap.String("version", version))
	svc := &oauthProxy{
		config:         config,
		log:            log,
		metricsHandler: promhttp.Handler(),
	}

	// parse the upstream endpoint
	if svc.endpoint, err = url.Parse(config.Upstream); err != nil {
		return nil, err
	}

	// initialize the store if any
	if config.StoreURL != "" {
		if svc.store, err = createStorage(config.StoreURL); err != nil {
			return nil, err
		}
	}

	// initialize the openid client
	if !config.SkipTokenVerification {
		if svc.client, svc.idp, svc.idpClient, err = svc.newOpenIDClient(); err != nil {
			return nil, err
		}
	} else {
		log.Warn("TESTING ONLY CONFIG - the verification of the token have been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warn("client credentials are not set, depending on provider (confidential|public) you might be unable to auth")
	}

	// are we running in forwarding mode?
	if config.EnableForwarding {
		if err := svc.createForwardingProxy(); err != nil {
			return nil, err
		}
	} else {
		if err := svc.createReverseProxy(); err != nil {
			return nil, err
		}
	}

	return svc, nil
}

// createLogger is responsible for creating the service logger
func createLogger(config *Config) (*zap.Logger, error) {
	httplog.SetOutput(ioutil.Discard) // disable the http logger
	if config.DisableAllLogging {
		return zap.NewNop(), nil
	}

	c := zap.NewProductionConfig()
	c.DisableStacktrace = true
	c.DisableCaller = true
	// Use human-readable timestamps in the logs until KEYCLOAK-12100 is fixed
	c.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	// are we enabling json logging?
	if !config.EnableJSONLogging {
		c.Encoding = "console"
	}
	// are we running verbose mode?
	if config.Verbose {
		httplog.SetOutput(os.Stderr)
		c.DisableCaller = false
		c.Development = true
		c.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	return c.Build()
}

// createReverseProxy creates a reverse proxy
func (r *oauthProxy) createReverseProxy() error {
	r.log.Info("enabled reverse proxy mode, upstream url", zap.String("url", r.config.Upstream))
	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}
	engine := chi.NewRouter()
	engine.MethodNotAllowed(emptyHandler)
	engine.NotFound(emptyHandler)
	engine.Use(middleware.Recoverer)
	// @check if the request tracking id middleware is enabled
	if r.config.EnableRequestID {
		r.log.Info("enabled the correlation request id middlware")
		engine.Use(r.requestIDMiddleware(r.config.RequestIDHeader))
	}
	// @step: enable the entrypoint middleware
	engine.Use(entrypointMiddleware)

	if r.config.EnableCompression {
		engine.Use(gzipMiddleware)
	}
	if r.config.EnableLogging {
		engine.Use(r.loggingMiddleware)
	}
	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware)
	}

	if len(r.config.CorsOrigins) > 0 {
		c := cors.New(cors.Options{
			AllowedOrigins:   r.config.CorsOrigins,
			AllowedMethods:   r.config.CorsMethods,
			AllowedHeaders:   r.config.CorsHeaders,
			AllowCredentials: r.config.CorsCredentials,
			ExposedHeaders:   r.config.CorsExposedHeaders,
			MaxAge:           int(r.config.CorsMaxAge.Seconds()),
			Debug:            r.config.Verbose,
		})
		engine.Use(c.Handler)
	}

	engine.Use(r.proxyMiddleware)
	r.router = engine

	if len(r.config.ResponseHeaders) > 0 {
		engine.Use(r.responseHeaderMiddleware(r.config.ResponseHeaders))
	}

	// step: add the routing for oauth
	engine.With(proxyDenyMiddleware).Route(r.config.BaseURI+r.config.OAuthURI, func(e chi.Router) {
		e.MethodNotAllowed(methodNotAllowHandlder)
		e.HandleFunc(authorizationURL, r.oauthAuthorizationHandler)
		e.Get(callbackURL, r.oauthCallbackHandler)
		e.Get(expiredURL, r.expirationHandler)
		e.Get(healthURL, r.healthHandler)
		e.With(r.authenticationMiddleware()).Get(logoutURL, r.logoutHandler)
		e.With(r.authenticationMiddleware()).Get(tokenURL, r.tokenHandler)
		e.Post(loginURL, r.loginHandler)
		if r.config.EnableMetrics {
			r.log.Info("enabled the service metrics middleware", zap.String("path", r.config.WithOAuthURI(metricsURL)))
			e.Get(metricsURL, r.proxyMetricsHandler)
		}
	})

	if r.config.EnableProfiling {
		engine.With(proxyDenyMiddleware).Route(debugURL, func(e chi.Router) {
			r.log.Warn("enabling the debug profiling on /debug/pprof")
			e.Get("/{name}", r.debugHandler)
			e.Post("/{name}", r.debugHandler)
		})
		// @check if the server write-timeout is still set and throw a warning
		if r.config.ServerWriteTimeout > 0 {
			r.log.Warn("you must disable the server write timeout (--server-write-timeout) when using pprof profiling")
		}
	}

	if r.config.EnableSessionCookies {
		r.log.Info("using session cookies only for access and refresh tokens")
	}

	// step: load the templates if any
	if err := r.createTemplates(); err != nil {
		return err
	}
	// step: provision in the protected resources
	enableDefaultDeny := r.config.EnableDefaultDeny
	for _, x := range r.config.Resources {
		if x.URL[len(x.URL)-1:] == "/" {
			r.log.Warn("the resource url is not a prefix",
				zap.String("resource", x.URL),
				zap.String("change", x.URL),
				zap.String("amended", strings.TrimRight(x.URL, "/")))
		}
		if x.URL == "/*" && r.config.EnableDefaultDeny {
			switch x.WhiteListed {
			case true:
				return errors.New("you've asked for a default denial but whitelisted everything")
			default:
				enableDefaultDeny = false
			}
		}
	}

	if enableDefaultDeny {
		r.log.Info("adding a default denial into the protected resources")
		r.config.Resources = append(r.config.Resources, &Resource{URL: "/*", Methods: allHTTPMethods})
	}

	for _, x := range r.config.Resources {
		r.log.Info("protecting resource", zap.String("resource", x.String()))
		e := engine.With(
			r.authenticationMiddleware(),
			r.admissionMiddleware(x),
			r.identityHeadersMiddleware(r.config.AddClaims))

		for _, m := range x.Methods {
			if !x.WhiteListed {
				e.MethodFunc(m, x.URL, emptyHandler)
				continue
			}
			engine.MethodFunc(m, x.URL, emptyHandler)
		}
	}

	for name, value := range r.config.MatchClaims {
		r.log.Info("token must contain", zap.String("claim", name), zap.String("value", value))
	}
	if r.config.RedirectionURL == "" {
		r.log.Warn("no redirection url has been set, will use host headers")
	}
	if r.config.EnableEncryptedToken {
		r.log.Info("session access tokens will be encrypted")
	}

	return nil
}

// createForwardingProxy creates a forwarding proxy
func (r *oauthProxy) createForwardingProxy() error {
	r.log.Info("enabling forward signing mode, listening on", zap.String("interface", r.config.Listen))

	if r.config.SkipUpstreamTLSVerify {
		r.log.Warn("tls verification switched off. In forward signing mode it's recommended you verify! (--skip-upstream-tls-verify=false)")
	}
	if err := r.createUpstreamProxy(nil); err != nil {
		return err
	}
	//nolint:bodyclose
	forwardingHandler := r.forwardProxyHandler()

	// set the http handler
	proxy := r.upstream.(*goproxy.ProxyHttpServer)
	r.router = proxy

	// setup the tls configuration
	if r.config.TLSCaCertificate != "" && r.config.TLSCaPrivateKey != "" {
		ca, err := loadCA(r.config.TLSCaCertificate, r.config.TLSCaPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to load certificate authority, error: %s", err)
		}

		// implement the goproxy connect method
		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectMitm,
					TLSConfig: goproxy.TLSConfigFromCA(ca),
				}, host
			},
		)
	} else {
		// use the default certificate provided by goproxy
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client errors
		if resp != nil && r.config.EnableLogging {
			start := ctx.UserData.(time.Time)
			latency := time.Since(start)
			latencyMetric.Observe(latency.Seconds())
			r.log.Info("client request",
				zap.String("method", resp.Request.Method),
				zap.String("path", resp.Request.URL.Path),
				zap.Int("status", resp.StatusCode),
				zap.Int64("bytes", resp.ContentLength),
				zap.String("host", resp.Request.Host),
				zap.String("path", resp.Request.URL.Path),
				zap.String("latency", latency.String()))
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		forwardingHandler(req, ctx.Resp)
		return req, ctx.Resp
	})

	return nil
}

// Run starts the proxy service
func (r *oauthProxy) Run() error {
	listener, err := r.createHTTPListener(listenerConfig{
		ca:                  r.config.TLSCaCertificate,
		certificate:         r.config.TLSCertificate,
		clientCert:          r.config.TLSClientCertificate,
		hostnames:           r.config.Hostnames,
		letsEncryptCacheDir: r.config.LetsEncryptCacheDir,
		listen:              r.config.Listen,
		privateKey:          r.config.TLSPrivateKey,
		proxyProtocol:       r.config.EnableProxyProtocol,
		redirectionURL:      r.config.RedirectionURL,
		useFileTLS:          r.config.TLSPrivateKey != "" && r.config.TLSCertificate != "",
		useLetsEncryptTLS:   r.config.UseLetsEncrypt,
		useSelfSignedTLS:    r.config.EnabledSelfSignedTLS,
	})

	if err != nil {
		return err
	}
	// step: create the http server
	server := &http.Server{
		Addr:         r.config.Listen,
		Handler:      r.router,
		ReadTimeout:  r.config.ServerReadTimeout,
		WriteTimeout: r.config.ServerWriteTimeout,
		IdleTimeout:  r.config.ServerIdleTimeout,
	}
	r.server = server
	r.listener = listener

	go func() {
		r.log.Info("Louketo proxy service starting", zap.String("interface", r.config.Listen))
		if err = server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				r.log.Fatal("failed to start the http service", zap.Error(err))
			}
		}
	}()

	// step: are we running http service as well?
	if r.config.ListenHTTP != "" {
		r.log.Info("Louketo proxy http service starting", zap.String("interface", r.config.ListenHTTP))
		httpListener, err := r.createHTTPListener(listenerConfig{
			listen:        r.config.ListenHTTP,
			proxyProtocol: r.config.EnableProxyProtocol,
		})
		if err != nil {
			return err
		}
		httpsvc := &http.Server{
			Addr:         r.config.ListenHTTP,
			Handler:      r.router,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}
		go func() {
			if err := httpsvc.Serve(httpListener); err != nil {
				r.log.Fatal("failed to start the http redirect service", zap.Error(err))
			}
		}()
	}

	return nil
}

// listenerConfig encapsulate listener options
type listenerConfig struct {
	ca                  string   // the path to a certificate authority
	certificate         string   // the path to the certificate if any
	clientCert          string   // the path to a client certificate to use for mutual tls
	hostnames           []string // list of hostnames the service will respond to
	letsEncryptCacheDir string   // the path to cache letsencrypt certificates
	listen              string   // the interface to bind the listener to
	privateKey          string   // the path to the private key if any
	proxyProtocol       bool     // whether to enable proxy protocol on the listen
	redirectionURL      string   // url to redirect to
	useFileTLS          bool     // indicates we are using certificates from files
	useLetsEncryptTLS   bool     // indicates we are using letsencrypt
	useSelfSignedTLS    bool     // indicates we are using the self-signed tls
}

// ErrHostNotConfigured indicates the hostname was not configured
var ErrHostNotConfigured = errors.New("acme/autocert: host not configured")

// createHTTPListener is responsible for creating a listening socket
func (r *oauthProxy) createHTTPListener(config listenerConfig) (net.Listener, error) {
	var listener net.Listener
	var err error

	// are we create a unix socket or tcp listener?
	if strings.HasPrefix(config.listen, "unix://") {
		socket := config.listen[7:]
		if exists := fileExists(socket); exists {
			if err = os.Remove(socket); err != nil {
				return nil, err
			}
		}
		r.log.Info("listening on unix socket", zap.String("interface", config.listen))
		if listener, err = net.Listen("unix", socket); err != nil {
			return nil, err
		}
	} else { //nolint:gocritic
		if listener, err = net.Listen("tcp", config.listen); err != nil {
			return nil, err
		}
	}

	// does it require proxy protocol?
	if config.proxyProtocol {
		r.log.Info("enabling the proxy protocol on listener", zap.String("interface", config.listen))
		listener = &proxyproto.Listener{Listener: listener}
	}

	// @check if the socket requires TLS
	if config.useSelfSignedTLS || config.useLetsEncryptTLS || config.useFileTLS {
		getCertificate := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("not configured")
		}

		if config.useLetsEncryptTLS {
			r.log.Info("enabling letsencrypt tls support")

			m := autocert.Manager{
				Prompt: autocert.AcceptTOS,
				Cache:  autocert.DirCache(config.letsEncryptCacheDir),
				HostPolicy: func(_ context.Context, host string) error {
					if len(config.hostnames) > 0 {
						found := false

						for _, h := range config.hostnames {
							found = found || (h == host)
						}

						if !found {
							return ErrHostNotConfigured
						}
					} else if config.redirectionURL != "" {
						if u, err := url.Parse(config.redirectionURL); err != nil {
							return err
						} else if u.Host != host {
							return ErrHostNotConfigured
						}
					}

					return nil
				},
			}

			getCertificate = m.GetCertificate
		}

		if config.useSelfSignedTLS {
			r.log.Info("enabling self-signed tls support", zap.Duration("expiration", r.config.SelfSignedTLSExpiration))

			rotate, err := newSelfSignedCertificate(r.config.SelfSignedTLSHostnames, r.config.SelfSignedTLSExpiration, r.log)
			if err != nil {
				return nil, err
			}
			getCertificate = rotate.GetCertificate
		}

		if config.useFileTLS {
			r.log.Info("tls support enabled", zap.String("certificate", config.certificate), zap.String("private_key", config.privateKey))
			rotate, err := newCertificateRotator(config.certificate, config.privateKey, r.log)
			if err != nil {
				return nil, err
			}
			// start watching the files for changes
			if err := rotate.watch(); err != nil {
				return nil, err
			}

			getCertificate = rotate.GetCertificate
		}

		tlsConfig := &tls.Config{
			GetCertificate:           getCertificate,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"h2", "http/1.1"},
		}

		listener = tls.NewListener(listener, tlsConfig)

		// @check if we doing mutual tls
		if config.clientCert != "" {
			caCert, err := ioutil.ReadFile(config.clientCert)
			if err != nil {
				return nil, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return listener, nil
}

// createUpstreamProxy create a reverse http proxy from the upstream
func (r *oauthProxy) createUpstreamProxy(upstream *url.URL) error {
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	// are we using a unix socket?
	if upstream != nil && upstream.Scheme == "unix" {
		r.log.Info("using unix socket for upstream", zap.String("socket", fmt.Sprintf("%s%s", upstream.Host, upstream.Path)))

		socketPath := fmt.Sprintf("%s%s", upstream.Host, upstream.Path)
		dialer = func(network, address string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		}
		upstream.Path = ""
		upstream.Host = "domain-sock"
		upstream.Scheme = unsecureScheme
	}
	// create the upstream tls configure
	//nolint:gas
	tlsConfig := &tls.Config{InsecureSkipVerify: r.config.SkipUpstreamTLSVerify}

	// are we using a client certificate
	// @TODO provide a means of reload on the client certificate when it expires. I'm not sure if it's just a
	// case of update the http transport settings - Also we to place this go-routine?
	if r.config.TLSClientCertificate != "" {
		cert, err := ioutil.ReadFile(r.config.TLSClientCertificate)
		if err != nil {
			r.log.Error("unable to read client certificate", zap.String("path", r.config.TLSClientCertificate), zap.Error(err))
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cert)
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	{
		// @check if we have a upstream ca to verify the upstream
		if r.config.UpstreamCA != "" {
			r.log.Info("loading the upstream ca", zap.String("path", r.config.UpstreamCA))
			ca, err := ioutil.ReadFile(r.config.UpstreamCA)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			tlsConfig.RootCAs = pool
		}
	}

	// create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()

	// headers formed by middleware before proxying to upstream shall be
	// kept in response. This is true for CORS headers ([KEYCOAK-9045])
	// and for refreshed cookies (htts://github.com/louketo/louketo-proxy/pulls/456])
	proxy.KeepDestinationHeaders = true
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	proxy.KeepDestinationHeaders = true
	r.upstream = proxy

	// update the tls configuration of the reverse proxy
	r.upstream.(*goproxy.ProxyHttpServer).Tr = &http.Transport{
		Dial:                  dialer,
		DisableKeepAlives:     !r.config.UpstreamKeepalives,
		ExpectContinueTimeout: r.config.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: r.config.UpstreamResponseHeaderTimeout,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.UpstreamTLSHandshakeTimeout,
		MaxIdleConns:          r.config.MaxIdleConns,
		MaxIdleConnsPerHost:   r.config.MaxIdleConnsPerHost,
	}

	return nil
}

// createTemplates loads the custom template
func (r *oauthProxy) createTemplates() error {
	var list []string

	if r.config.SignInPage != "" {
		r.log.Debug("loading the custom sign in page", zap.String("page", r.config.SignInPage))
		list = append(list, r.config.SignInPage)
	}

	if r.config.ForbiddenPage != "" {
		r.log.Debug("loading the custom sign forbidden page", zap.String("page", r.config.ForbiddenPage))
		list = append(list, r.config.ForbiddenPage)
	}

	if len(list) > 0 {
		r.log.Info("loading the custom templates", zap.String("templates", strings.Join(list, ",")))
		r.templates = template.Must(template.ParseFiles(list...))
	}

	return nil
}

// newOpenIDClient initializes the openID configuration, note: the redirection url is deliberately left blank
// in order to retrieve it from the host header on request
func (r *oauthProxy) newOpenIDClient() (*oidc.Client, oidc.ProviderConfig, *http.Client, error) {
	var err error
	var config oidc.ProviderConfig

	// step: fix up the url if required, the underlining lib will add the .well-known/openid-configuration to the discovery url for us.
	if strings.HasSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration") {
		r.config.DiscoveryURL = strings.TrimSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration")
	}

	// step: create a idp http client
	hc := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				if r.config.OpenIDProviderProxy != "" {
					idpProxyURL, erp := url.Parse(r.config.OpenIDProviderProxy)
					if erp != nil {
						r.log.Warn("invalid proxy address for open IDP provider proxy", zap.Error(erp))
						return nil, nil
					}
					return idpProxyURL, nil
				}

				return nil, nil
			},
			TLSClientConfig: &tls.Config{
				//nolint:gas
				InsecureSkipVerify: r.config.SkipOpenIDProviderTLSVerify,
			},
		},
		Timeout: time.Second * 10,
	}

	// step: attempt to retrieve the provider configuration
	completeCh := make(chan bool)
	go func() {
		for {
			r.log.Info("attempting to retrieve configuration discovery url",
				zap.String("url", r.config.DiscoveryURL),
				zap.String("timeout", r.config.OpenIDProviderTimeout.String()))
			if config, err = oidc.FetchProviderConfig(hc, r.config.DiscoveryURL); err == nil {
				break // break and complete
			}
			r.log.Warn("failed to get provider configuration from discovery", zap.Error(err))
			time.Sleep(time.Second * 3)
		}
		completeCh <- true
	}()
	// wait for timeout or successful retrieval
	select {
	case <-time.After(r.config.OpenIDProviderTimeout):
		return nil, config, nil, errors.New("failed to retrieve the provider configuration from discovery url")
	case <-completeCh:
		r.log.Info("successfully retrieved openid configuration from the discovery")
	}

	client, err := oidc.NewClient(oidc.ClientConfig{
		Credentials: oidc.ClientCredentials{
			ID:     r.config.ClientID,
			Secret: r.config.ClientSecret,
		},
		HTTPClient:     hc,
		RedirectURL:    fmt.Sprintf("%s/oauth/callback", r.config.RedirectionURL),
		ProviderConfig: config,
		Scope:          append(r.config.Scopes, oidc.DefaultScope...),
	})
	if err != nil {
		return nil, config, hc, err
	}
	// start the provider sync for key rotation
	client.SyncProviderConfig(r.config.DiscoveryURL)

	return client, config, hc, nil
}

// Render implements the echo Render interface
func (r *oauthProxy) Render(w io.Writer, name string, data interface{}) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

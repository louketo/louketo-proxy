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

	"golang.org/x/crypto/acme/autocert"

	httplog "log"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/coreos/go-oidc/oidc"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/oneconcern/keycloak-gatekeeper/version"
	"go.uber.org/zap"
)

type oauthProxy struct {
	client      *oidc.Client
	config      *Config
	endpoint    *url.URL
	idp         oidc.ProviderConfig
	idpClient   *http.Client
	listener    net.Listener
	log         *zap.Logger
	router      http.Handler
	adminRouter http.Handler
	server      *http.Server
	store       storage
	templates   *template.Template
	upstream    reverseProxy
	csrf        func(http.Handler) http.Handler
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU()) // set the core
}

// newProxy create's a new proxy from configuration
func newProxy(config *Config) (*oauthProxy, error) {
	// create the service logger
	log, err := createLogger(config)
	if err != nil {
		return nil, err
	}

	log.Info("starting the service", zap.String("prog", version.Prog), zap.String("author", version.Author), zap.String("version", version.GetVersion()))
	svc := &oauthProxy{
		config: config,
		log:    log,
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
		log.Warn("TESTING ONLY CONFIG - access token verification has been disabled")
	}

	if config.ClientID == "" && config.ClientSecret == "" {
		log.Warn("client credentials are not set, depending on provider (confidential|public) you might be unable to auth")
	}

	if config.EnableForwarding {
		// runs forward proxy mode
		if err := svc.createForwardingProxy(); err != nil {
			return nil, err
		}
	} else {
		// runs reverse proxy mode
		if err := svc.createReverseProxy(); err != nil {
			return nil, err
		}

		// publish health, metrics and profiling endpoints
		svc.createAdminServices()
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

// useDefaultStack sets the default middleware stack for router
func (r *oauthProxy) useDefaultStack(engine chi.Router) {
	engine.MethodNotAllowed(emptyHandler)
	engine.NotFound(emptyHandler)
	engine.Use(middleware.Recoverer)

	// @check if the request tracking id middleware is enabled
	if r.config.EnableRequestID {
		r.log.Info("enabled the correlation request id middleware")
		engine.Use(r.requestIDMiddleware(r.config.RequestIDHeader))
	}
	// @step: enable the entrypoint middleware
	engine.Use(entrypointMiddleware)

	if r.config.EnableLogging {
		engine.Use(r.loggingMiddleware)
	}

	if r.config.EnableSecurityFilter {
		engine.Use(r.securityMiddleware)
	}
}

// Run starts the proxy service
func (r *oauthProxy) Run() error {
	listener, err := r.createHTTPListener(makeListenerConfig(r.config))
	if err != nil {
		return fmt.Errorf("could not start main service: %v", err)
	}

	// step: create the main http(s) server
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
		r.log.Info("keycloak proxy service starting", zap.String("interface", r.config.Listen))
		if err = server.Serve(listener); err != nil {
			if err != http.ErrServerClosed {
				r.log.Fatal("failed to start the http service", zap.Error(err))
			}
		}
	}()

	// step: are we running http service as well?
	if r.config.ListenHTTP != "" {
		r.log.Info("keycloak proxy http service starting", zap.String("interface", r.config.ListenHTTP))
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

	// step: are we running specific admin service as well?
	// if not, admin endpoints are added as routes in the main service
	if r.config.ListenAdmin != "" {
		r.log.Info("keycloak proxy admin service starting", zap.String("interface", r.config.ListenAdmin))
		var (
			adminListener net.Listener
			err           error
		)

		r.log.Info("server admin service with scheme:", zap.String("scheme", r.config.ListenAdminScheme))
		if r.config.ListenAdminScheme == unsecureScheme {
			// run the admin endpoint (metrics, health) with http
			adminListener, err = r.createHTTPListener(listenerConfig{
				listen:        r.config.ListenAdmin,
				proxyProtocol: r.config.EnableProxyProtocol,
			})
			if err != nil {
				return err
			}
		} else {
			adminListenerConfig := makeListenerConfig(r.config)

			// admin specific overides
			adminListenerConfig.listen = r.config.ListenAdmin

			// TLS configuration defaults to the one for the main service,
			// and may be overidden
			if r.config.TLSAdminPrivateKey != "" && r.config.TLSAdminCertificate != "" {
				adminListenerConfig.useFileTLS = true
				adminListenerConfig.certificate = r.config.TLSAdminCertificate
				adminListenerConfig.privateKey = r.config.TLSAdminPrivateKey
			}
			if r.config.TLSAdminCaCertificate != "" {
				adminListenerConfig.ca = r.config.TLSAdminCaCertificate
			}
			if r.config.TLSAdminClientCertificate != "" {
				adminListenerConfig.clientCerts = []string{r.config.TLSAdminClientCertificate}
			}
			if len(r.config.TLSAdminClientCertificates) > 0 {
				adminListenerConfig.clientCerts = r.config.TLSAdminClientCertificates
			}
			adminListener, err = r.createHTTPListener(adminListenerConfig)
			if err != nil {
				return err
			}
		}
		adminsvc := &http.Server{
			Addr:         r.config.ListenAdmin,
			Handler:      r.adminRouter,
			ReadTimeout:  r.config.ServerReadTimeout,
			WriteTimeout: r.config.ServerWriteTimeout,
			IdleTimeout:  r.config.ServerIdleTimeout,
		}

		go func() {
			if ers := adminsvc.Serve(adminListener); ers != nil {
				r.log.Fatal("failed to start the admin service", zap.Error(ers))
			}
		}()
	}
	return nil
}

// listenerConfig encapsulate listener options
type listenerConfig struct {
	ca                  string   // the path to a certificate authority
	certificate         string   // the path to the certificate if any
	clientCerts         []string // the paths to client certificates to use for mutual tls
	hostnames           []string // list of hostnames the service will respond to
	letsEncryptCacheDir string   // the path to cache letsencrypt certificates
	listen              string   // the interface to bind the listener to
	privateKey          string   // the path to the private key if any
	proxyProtocol       bool     // whether to enable proxy protocol on the listen
	redirectionURL      string   // url to redirect to
	useFileTLS          bool     // indicates we are using certificates from files
	useLetsEncryptTLS   bool     // indicates we are using letsencrypt
	useSelfSignedTLS    bool     // indicates we are using the self-signed tls

	// advanced TLS settings
	*tlsAdvancedConfig
}

// makeListenerConfig extracts a listener configuration from a proxy Config
func makeListenerConfig(config *Config) listenerConfig {
	cfg := listenerConfig{
		hostnames:           config.Hostnames,
		letsEncryptCacheDir: config.LetsEncryptCacheDir,
		listen:              config.Listen,
		proxyProtocol:       config.EnableProxyProtocol,
		redirectionURL:      config.RedirectionURL,
		privateKey:          config.TLSPrivateKey,

		// TLS settings
		useFileTLS:        config.TLSPrivateKey != "" && config.TLSCertificate != "",
		ca:                config.TLSCaCertificate,
		certificate:       config.TLSCertificate,
		clientCerts:       nil,
		useLetsEncryptTLS: config.UseLetsEncrypt,
		useSelfSignedTLS:  config.EnabledSelfSignedTLS,
		tlsAdvancedConfig: &tlsAdvancedConfig{
			tlsMinVersion:               config.TLSMinVersion,
			tlsCurvePreferences:         config.TLSCurvePreferences,
			tlsCipherSuites:             config.TLSCipherSuites,
			tlsUseModernSettings:        config.TLSUseModernSettings,
			tlsPreferServerCipherSuites: config.TLSPreferServerCipherSuites,
		},
	}
	if config.TLSClientCertificate != "" {
		cfg.clientCerts = []string{config.TLSClientCertificate}
	}
	if len(config.TLSClientCertificates) > 0 {
		cfg.clientCerts = config.TLSClientCertificates
	}
	return cfg
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
	} else if listener, err = net.Listen("tcp", config.listen); err != nil {
		return nil, err
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
				r.log.Error("error while setting certificate rotator", zap.Error(err))
				return nil, err
			}
			// start watching the files for changes
			if err := rotate.watch(); err != nil {
				r.log.Error("error while setting file watch on certificate", zap.Error(err))
				return nil, err
			}

			getCertificate = rotate.GetCertificate
		}

		ts, err := parseTLS(config.tlsAdvancedConfig)
		if err != nil {
			return nil, err
		}

		tlsConfig := &tls.Config{
			GetCertificate: getCertificate,
			// Causes servers to use Go's default ciphersuite preferences,
			// which are tuned to avoid attacks. Does nothing on clients.
			//nolint:gas
			PreferServerCipherSuites: ts.tlsPreferServerCipherSuites,
			CurvePreferences:         ts.tlsCurvePreferences,
			NextProtos:               []string{"h2", "http/1.1"},
			MinVersion:               ts.tlsMinVersion,
			CipherSuites:             ts.tlsCipherSuites,
		}

		// @check if we are doing mutual tls
		if len(config.clientCerts) > 0 {
			r.log.Info("enabling mutual tls support with client certs")
			caCertPool, erp := makeCertPool("client", config.clientCerts...)
			if erp != nil {
				r.log.Error("unable to read client CA certificate", zap.Error(erp))
				return nil, erp
			}
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		listener = tls.NewListener(listener, tlsConfig)
	}
	return listener, nil
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

	// step: fix up the url if required, the underlying lib will add the .well-known/openid-configuration to the discovery url for us.
	if strings.HasSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration") {
		r.config.DiscoveryURL = strings.TrimSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration")
	}

	// step: create a idp http client
	var pool *x509.CertPool
	if r.config.OpenIDProviderCA != "" {
		pool, err = makeCertPool("OpenID provider", r.config.OpenIDProviderCA)
		if err != nil {
			r.log.Error("unable to read OpenIDProvider CA certificate", zap.String("path", r.config.OpenIDProviderCA), zap.Error(err))
			return nil, config, nil, err
		}
	}
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
				RootCAs:            pool,
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

func (r *oauthProxy) buildProxyTLSConfig() (*tls.Config, error) {
	//nolint:gas
	tlsConfig := &tls.Config{InsecureSkipVerify: r.config.SkipUpstreamTLSVerify}

	// are we using a client certificate?
	// @TODO provide a means to reload the client certificate when it expires. I'm not sure if it's just a
	// case of update the http transport settings - Also where to place this go-routine?
	if r.config.TLSClientCertificate != "" {
		pool, err := makeCertPool("client", r.config.TLSClientCertificate)
		if err != nil {
			r.log.Error("unable to read client certificate", zap.String("path", r.config.TLSClientCertificate), zap.Error(err))
			return nil, err
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// @check if we have an upstream ca to verify the upstream
	if r.config.UpstreamCA != "" {
		r.log.Info("loading the upstream ca", zap.String("path", r.config.UpstreamCA))
		pool, err := makeCertPool("upstream CA", r.config.UpstreamCA)
		if err != nil {
			r.log.Error("unable to read upstream CA certificate", zap.String("path", r.config.UpstreamCA), zap.Error(err))
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

func makeCertPool(who string, certs ...string) (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	for _, cert := range certs {
		caPEMCert, err := ioutil.ReadFile(cert)
		if err != nil {
			return nil, fmt.Errorf("cannot read cert file for %s: %q: %v", who, cert, err)
		}
		ok := caCertPool.AppendCertsFromPEM(caPEMCert)
		if !ok {
			return nil, fmt.Errorf("invalid %s PEM certificate", who)
		}
	}
	return caCertPool, nil
}

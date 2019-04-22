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
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rs/cors"
	"go.uber.org/zap"
)

// createReverseProxy creates a reverse proxy
func (r *oauthProxy) createReverseProxy() error {
	r.log.Info("enabled reverse proxy mode, default upstream url", zap.String("url", r.config.Upstream))
	if err := r.createUpstreamProxy(r.endpoint); err != nil {
		return err
	}
	engine := chi.NewRouter()
	r.useDefaultStack(engine)

	// @step: configure CORS middleware
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

	r.router = engine

	if len(r.config.ResponseHeaders) > 0 {
		engine.Use(r.responseHeaderMiddleware(r.config.ResponseHeaders))
	}

	// configure CSRF middleware
	r.csrf = r.csrfConfigMiddleware()

	// step: define admin subrouter: health and metrics
	adminEngine := chi.NewRouter()
	r.log.Info("enabled health service", zap.String("path", path.Clean(r.config.WithOAuthURI(healthURL))))
	adminEngine.Get(healthURL, r.healthHandler)
	if r.config.EnableMetrics {
		r.log.Info("enabled the service metrics middleware", zap.String("path", path.Clean(r.config.WithOAuthURI(metricsURL))))
		adminEngine.Get(metricsURL, r.proxyMetricsHandler)
	}

	// step: add the routing for oauth
	engine.With(
		proxyDenyMiddleware,
		r.csrfSkipMiddleware(), // handle CSRF state, but skip check on POST endpoints below
		r.csrfProtectMiddleware(),
		r.csrfHeaderMiddleware()).Route(r.config.OAuthURI, func(e chi.Router) {
		e.MethodNotAllowed(methodNotAllowHandlder)
		e.HandleFunc(authorizationURL, r.oauthAuthorizationHandler)
		e.Get(callbackURL, r.oauthCallbackHandler)
		e.Get(expiredURL, r.expirationHandler)

		e.With(r.authenticationMiddleware()).Get(logoutURL, r.logoutHandler)
		e.With(r.authenticationMiddleware()).Get(tokenURL, r.tokenHandler)

		e.Post(loginURL, r.loginHandler)

		if r.config.ListenAdmin == "" {
			e.Mount("/", adminEngine)
		}
	})

	// step: define profiling subrouter
	var debugEngine chi.Router
	if r.config.EnableProfiling {
		r.log.Warn("enabling the debug profiling on " + debugURL)
		debugEngine = chi.NewRouter()
		debugEngine.Get("/{name}", r.debugHandler)
		debugEngine.Post("/{name}", r.debugHandler)

		// @check if the server write-timeout is still set and throw a warning
		if r.config.ServerWriteTimeout > 0 {
			r.log.Warn("you should disable the server write timeout (--server-write-timeout) when using pprof profiling")
		}
		if r.config.ListenAdmin == "" {
			engine.With(proxyDenyMiddleware).Mount(debugURL, debugEngine)
		}
	}

	if r.config.ListenAdmin != "" {
		// mount admin and debug engines separately
		r.log.Info("mounting admin endpoints on separate listener")
		admin := chi.NewRouter()
		admin.MethodNotAllowed(emptyHandler)
		admin.NotFound(emptyHandler)
		admin.Use(middleware.Recoverer)
		admin.Use(proxyDenyMiddleware)
		admin.Route("/", func(e chi.Router) {
			e.Mount(r.config.OAuthURI, adminEngine)
			if debugEngine != nil {
				e.Mount(debugURL, debugEngine)
			}
		})
		r.adminRouter = admin
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
		r.log.Info("adding a default denial to protected resources: all routes to upstream require authentication")
		r.config.Resources = append(r.config.Resources, &Resource{URL: "/*", Methods: allHTTPMethods})
	} else {
		r.log.Info("routes to upstream are not configured to be denied by default")
		engine.With(r.proxyMiddleware(nil)).HandleFunc("/*", emptyHandler)
	}

	for _, x := range r.config.Resources {
		r.log.Info("protecting resource", zap.String("resource", x.String()))
		if !x.WhiteListed {
			e := engine.With(
				r.proxyMiddleware(x),
				r.authenticationMiddleware(),
				r.admissionMiddleware(x),
				r.identityHeadersMiddleware(r.config.AddClaims),
				r.csrfSkipResourceMiddleware(x),
				r.csrfProtectMiddleware(),
				r.csrfHeaderMiddleware())
			e.Handle(x.URL, chi.NewMux().MethodNotAllowedHandler())
			for _, m := range x.Methods {
				e.MethodFunc(m, x.URL, emptyHandler)
			}
		} else {
			e := engine.With(
				r.proxyMiddleware(x))
			e.Handle(x.URL, chi.NewMux().MethodNotAllowedHandler())
			for _, m := range x.Methods {
				e.MethodFunc(m, x.URL, emptyHandler)
			}
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

// proxyMiddleware is responsible for handles reverse proxy request to the upstream endpoint
func (r *oauthProxy) proxyMiddleware(resource *Resource) func(http.Handler) http.Handler {
	var upstreamHost, upstreamScheme, upstreamBasePath, stripBasePath, matched string
	if resource != nil && resource.Upstream != "" {
		// resource-specific routing to upstream
		u, _ := url.Parse(resource.Upstream)
		matched = resource.URL
		upstreamHost = u.Host
		upstreamScheme = u.Scheme
		upstreamBasePath = u.Path
	} else {
		// default routing
		upstreamHost = r.endpoint.Host
		upstreamScheme = r.endpoint.Scheme
		upstreamBasePath = r.endpoint.Path
	}
	if resource != nil {
		stripBasePath = resource.StripBasePath
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)

			// @step: retrieve the request scope
			scope := req.Context().Value(contextScopeName)
			if scope != nil {
				sc := scope.(*RequestScope)
				if sc.AccessDenied {
					return
				}
			}

			// @step: add the proxy forwarding headers
			req.Header.Add("X-Forwarded-For", realIP(req))
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-Proto", req.Header.Get("X-Forwarded-Proto"))

			if len(r.config.CorsOrigins) > 0 {
				// if CORS is enabled by gatekeeper, do not propagate CORS requests upstream
				req.Header.Del("Origin")
			}
			// @step: add any custom headers to the request
			for k, v := range r.config.Headers {
				req.Header.Set(k, v)
			}

			if r.config.EnableCSRF {
				// remove csrf header
				req.Header.Del(r.config.CSRFHeader)
				if !r.config.EnableAuthorizationCookies {
					_ = filterCookies(req, []string{requestURICookie, r.config.CSRFCookieName})
				}
			} else if !r.config.EnableAuthorizationCookies {
				_ = filterCookies(req, []string{requestURICookie})
			}

			req.URL.Host = upstreamHost
			req.URL.Scheme = upstreamScheme
			if stripBasePath != "" {
				// strip prefix if needed
				req.URL.Path = strings.TrimPrefix(stripBasePath, req.URL.Path)
			}
			if upstreamBasePath != "" {
				// add upstream URL component if any
				req.URL.Path = path.Join(upstreamBasePath, req.URL.Path)
			}
			r.log.Debug("proxying to upstream", zap.String("matched_resource", matched), zap.Stringer("upstream_url", req.URL))

			// @note: by default goproxy only provides a forwarding proxy, thus all requests have to be absolute and we must update the host headers
			// TODO(fredbi): weakness here
			if v := req.Header.Get("Host"); v != "" {
				req.Host = v
				req.Header.Del("Host")
			} else if !r.config.PreserveHost {
				req.Host = upstreamHost
			}
			r.log.Debug("host", zap.String("host", req.Host))

			if isUpgradedConnection(req) {
				r.log.Debug("upgrading the connnection", zap.String("client_ip", req.RemoteAddr))
				if err := tryUpdateConnection(req, w, req.URL); err != nil {
					r.log.Error("failed to upgrade connection", zap.Error(err))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				return
			}

			r.upstream.ServeHTTP(w, req)
		})
	}
}

package main

import (
	"path"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
)

// createAdminServices creates administrative endpoints
func (r *oauthProxy) createAdminServices() {
	if r.config.ListenAdmin != "" {
		// mount admin and debug engines separately
		r.log.Info("mounting admin endpoints on separate listener")
		adminEngine := chi.NewRouter()
		adminEngine.MethodNotAllowed(emptyHandler)
		adminEngine.NotFound(emptyHandler)
		adminEngine.Use(middleware.Recoverer)
		adminEngine.Use(proxyDenyMiddleware)

		adminEngine.Route(r.config.OAuthURI,
			func(e chi.Router) {
				e.Mount("/", r.createAdminRoutes())
			})
		if debugEngine := r.createDebugRoutes(); debugEngine != nil {
			adminEngine.Mount(debugURL, debugEngine)
		}
		r.adminRouter = adminEngine
	} else {
		r.log.Info("mounting admin endpoints on main reverse proxy listener")
	}

}

func (r *oauthProxy) createAdminRoutes() chi.Router {
	admin := chi.NewRouter()
	// step: health
	r.log.Info("enabling health service", zap.String("path", path.Clean(r.config.WithOAuthURI(healthURL))))
	admin.Get(healthURL, r.healthHandler)

	// step: metrics
	if r.config.EnableMetrics {
		r.log.Info("enabling metrics service", zap.String("path", path.Clean(r.config.WithOAuthURI(metricsURL))))
		admin.Get(metricsURL, r.proxyMetricsHandler)
	}
	return admin
}

func (r *oauthProxy) createDebugRoutes() chi.Router {
	// step: define profiling endpoints
	var debugEngine chi.Router
	if r.config.EnableProfiling {
		r.log.Warn("enabling debug profiling", zap.String("path", debugURL))
		debugEngine = chi.NewRouter()
		debugEngine.Get("/{name}", r.debugHandler)
		debugEngine.Post("/{name}", r.debugHandler)

		// @check if the server write-timeout is still set and throw a warning
		if r.config.ServerWriteTimeout > 0 {
			r.log.Warn("you should disable the server write timeout (--server-write-timeout) when using pprof profiling")
		}
	}
	return debugEngine
}

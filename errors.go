package main

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"

	"go.uber.org/zap"
)

func methodNotAllowedHandler(w http.ResponseWriter, req *http.Request) {
	errorResponse(w, "", http.StatusMethodNotAllowed)
	_, _ = w.Write(nil)
}

func methodNotFoundHandler(w http.ResponseWriter, req *http.Request) {
	errorResponse(w, "", http.StatusNotFound)
	_, _ = w.Write(nil)
}

func (r *oauthProxy) errorResponse(w http.ResponseWriter, msg string, code int, err error) {
	if err == nil {
		r.log.Warn(msg, zap.Int("http_status", code))
	} else {
		if code == http.StatusInternalServerError {
			// we log internal server errors as ERRROR
			r.log.Error(msg, zap.Int("http_status", code), zap.Error(err))
		} else {
			// we log user errors as WARNING
			r.log.Warn(msg, zap.Int("http_status", code), zap.Error(err))
		}
	}
	errorResponse(w, msg, code)
}

func errorResponse(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", jsonMime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if len(msg) > 0 {
		fmt.Fprintln(w, fmt.Sprintf(`{%q}`, msg))
	}
}

// accessForbidden redirects the user to the forbidden page
func (r *oauthProxy) accessForbidden(w http.ResponseWriter, req *http.Request, msgs ...string) context.Context {
	// are we using a custom http template for 403?
	if r.config.hasCustomForbiddenPage() {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		name := path.Base(r.config.ForbiddenPage)
		if err := r.Render(w, name, r.config.Tags); err != nil {
			r.log.Error("failed to render the template", zap.Error(err), zap.String("template", name))
		}
	} else {
		var msg string
		if len(msgs) > 0 {
			msg = msgs[0]
			if len(msgs) > 1 {
				// extraMsg goes to log but not to return end user error
				extraMsg := strings.Join(msgs[1:], " ")
				r.log.Warn(extraMsg)
			}
		}
		r.errorResponse(w, msg, http.StatusForbidden, nil)
	}
	return r.revokeProxy(w, req)
}

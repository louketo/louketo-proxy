package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"go.uber.org/zap"
)

var (
	// ErrSessionNotFound no session found in the request
	ErrSessionNotFound = errors.New("authentication session not found")
	// ErrNoSessionStateFound means there was not persist state
	ErrNoSessionStateFound = errors.New("no session state found")
	// ErrInvalidSession the session is invalid
	ErrInvalidSession = errors.New("invalid session identifier")
	// ErrAccessTokenExpired indicates the access token has expired
	ErrAccessTokenExpired = errors.New("the access token has expired")
	// ErrRefreshTokenExpired indicates the refresh token as expired
	ErrRefreshTokenExpired = errors.New("the refresh token has expired")
	// ErrNoTokenAudience indicates their is not audience in the token
	ErrNoTokenAudience = errors.New("the token does not audience in claims")
	// ErrDecryption indicates we can't decrypt the token
	ErrDecryption = errors.New("failed to decrypt token")
	// ErrEncode indicates a failure to encode the token
	ErrEncode = errors.New("failed to encode token")
	// ErrEncryption indicates a failure to encrypt the token
	ErrEncryption = errors.New("failed to encrypt token")
)

func methodNotAllowedHandler(w http.ResponseWriter, req *http.Request) {
	errorResponse(w, "", http.StatusMethodNotAllowed)
	_, _ = w.Write(nil)
}

func methodNotFoundHandler(w http.ResponseWriter, req *http.Request) {
	errorResponse(w, "", http.StatusNotFound)
	_, _ = w.Write(nil)
}

func (r *oauthProxy) errorResponse(w http.ResponseWriter, req *http.Request, msg string, code int, err error) {
	span, logger := r.traceSpanRequest(req)

	if err == nil {
		logger.Warn(msg, zap.Int("http_status", code))
	} else {
		switch code {
		case http.StatusInternalServerError:
			// we log internal server errors as ERROR
			logger.Error(msg, zap.Int("http_status", code), zap.Error(err))
		default:
			// we log user errors as WARNING
			logger.Warn(msg, zap.Int("http_status", code), zap.Error(err))
		}
	}

	if span != nil {
		traceError(span, err, code)
	}

	errorResponse(w, msg, code)
}

func errorResponse(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", jsonMime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	if len(msg) > 0 {
		fmt.Fprintln(w, fmt.Sprintf(`{"error": %q}`, msg))
	}
}

// accessForbidden redirects the user to the forbidden page
func (r *oauthProxy) accessForbidden(w http.ResponseWriter, req *http.Request, msgs ...string) context.Context {
	_, logger := r.traceSpanRequest(req)

	// are we using a custom http template for 403?
	if r.config.hasCustomForbiddenPage() {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusForbidden)
		name := path.Base(r.config.ForbiddenPage)
		if err := r.Render(w, name, r.config.Tags); err != nil {
			logger.Error("failed to render the template", zap.Error(err), zap.String("template", name))
		}
	} else {
		var msg string
		if len(msgs) > 0 {
			msg = msgs[0]
			if len(msgs) > 1 {
				// extraMsg goes to log but not to be returned as end user error
				extraMsg := strings.Join(msgs[1:], " ")
				r.log.Warn(extraMsg)
			}
		}
		r.errorResponse(w, req, msg, http.StatusForbidden, nil)
	}
	return r.revokeProxy(w, req)
}

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

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gambol99/keycloak-proxy/pkg/constants"
	"github.com/gambol99/keycloak-proxy/pkg/utils"

	"github.com/gambol99/go-oidc/oauth2"
	"github.com/pressly/chi"
	"go.uber.org/zap"
)

// getRedirectionURL returns the redirectionURL for the oauth flow
func (r *oauthProxy) getRedirectionURL(w http.ResponseWriter, req *http.Request) string {
	var redirect string
	switch r.config.RedirectionURL {
	case "":
		scheme := constants.HTTPSchema
		if req.TLS != nil {
			scheme = constants.HTTPSSchema
		}
		// @QUESTION: should I use the X-Forwarded-<header>?? ..
		redirect = fmt.Sprintf("%s://%s",
			utils.DefaultTo(req.Header.Get("X-Forwarded-Proto"), scheme),
			utils.DefaultTo(req.Header.Get("X-Forwarded-Host"), req.Host))
	default:
		redirect = r.config.RedirectionURL
	}

	return fmt.Sprintf("%s/oauth/callback", redirect)
}

// oauthAuthorizationHandler is responsible for performing the redirection to oauth provider
func (r *oauthProxy) oauthAuthorizationHandler(w http.ResponseWriter, req *http.Request) {
	if r.config.SkipTokenVerification {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	client, err := r.getOAuthClient(r.getRedirectionURL(w, req))
	if err != nil {
		r.log.Error("failed to retrieve the oauth client for authorization", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// step: set the access type of the session
	var accessType string
	if utils.ContainedIn("offline", r.config.Scopes) {
		accessType = "offline"
	}

	authURL := client.AuthCodeURL(req.URL.Query().Get("state"), accessType, "")
	r.log.Debug("incoming authorization request from client address",
		zap.String("access_type", accessType),
		zap.String("auth_url", authURL),
		zap.String("client_ip", req.RemoteAddr))

	// step: if we have a custom sign in page, lets display that
	if r.config.HasCustomSignInPage() {
		model := make(map[string]string)
		model["redirect"] = authURL
		w.WriteHeader(http.StatusOK)
		r.Render(w, path.Base(r.config.SignInPage), utils.MergeMaps(model, r.config.Tags))
		return
	}

	r.redirectToURL(authURL, w, req)
}

// oauthCallbackHandler is responsible for handling the response from oauth service
func (r *oauthProxy) oauthCallbackHandler(w http.ResponseWriter, req *http.Request) {
	if r.config.SkipTokenVerification {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	// step: ensure we have a authorization code
	code := req.URL.Query().Get("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	client, err := r.getOAuthClient(r.getRedirectionURL(w, req))
	if err != nil {
		r.log.Error("unable to create a oauth2 client", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, err := exchangeAuthenticationCode(client, code)
	if err != nil {
		r.log.Error("unable to exchange code for access token", zap.Error(err))
		r.accessForbidden(w, req)
		return
	}

	// Flow: once we exchange the authorization code we parse the ID Token; we then check for a access token,
	// if a access token is present and we can decode it, we use that as the session token, otherwise we default
	// to the ID Token.
	token, identity, err := parseToken(resp.IDToken)
	if err != nil {
		r.log.Error("unable to parse id token for identity", zap.Error(err))
		r.accessForbidden(w, req)
		return
	}
	access, id, err := parseToken(resp.AccessToken)
	if err == nil {
		token = access
		identity = id
	} else {
		r.log.Warn("unable to parse the access token, using id token only", zap.Error(err))
	}

	// step: check the access token is valid
	if err = verifyToken(r.client, token); err != nil {
		r.log.Error("unable to verify the id token", zap.Error(err))
		r.accessForbidden(w, req)
		return
	}
	accessToken := token.Encode()

	// step: are we encrypting the access token?
	if r.config.EnableEncryptedToken {
		if accessToken, err = utils.EncodeText(accessToken, r.config.EncryptionKey); err != nil {
			r.log.Error("unable to encode the access token", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	r.log.Info("issuing access token for user",
		zap.String("email", identity.Email),
		zap.String("expires", identity.ExpiresAt.Format(time.RFC3339)),
		zap.String("duration", time.Until(identity.ExpiresAt).String()))

	// step: does the response has a refresh token and we are NOT ignore refresh tokens?
	if r.config.EnableRefreshTokens && resp.RefreshToken != "" {
		var encrypted string
		encrypted, err = utils.EncodeText(resp.RefreshToken, r.config.EncryptionKey)
		if err != nil {
			r.log.Error("failed to encrypt the refresh token", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// drop in the access token - cookie expiration = access token
		r.dropAccessTokenCookie(req, w, accessToken, r.getAccessCookieExpiration(token, resp.RefreshToken))

		switch r.useStore() {
		case true:
			if err = r.StoreRefreshToken(token, encrypted); err != nil {
				r.log.Warn("failed to save the refresh token in the store", zap.Error(err))
			}
		default:
			// notes: not all idp refresh tokens are readable, google for example, so we attempt to decode into
			// a jwt and if possible extract the expiration, else we default to 10 days
			if _, ident, err := parseToken(resp.RefreshToken); err != nil {
				r.dropRefreshTokenCookie(req, w, encrypted, time.Duration(240)*time.Hour)
			} else {
				r.dropRefreshTokenCookie(req, w, encrypted, time.Until(ident.ExpiresAt))
			}
		}
	} else {
		r.dropAccessTokenCookie(req, w, accessToken, time.Until(identity.ExpiresAt))
	}

	// step: decode the state variable
	state := "/"
	if req.URL.Query().Get("state") != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.URL.Query().Get("state"))
		if err != nil {
			r.log.Warn("unable to decode the state parameter",
				zap.String("state", req.URL.Query().Get("state")),
				zap.Error(err))
		} else {
			state = string(decoded)
		}
	}

	r.redirectToURL(state, w, req)
}

// loginHandler provide's a generic endpoint for clients to perform a user_credentials login to the provider
func (r *oauthProxy) loginHandler(w http.ResponseWriter, req *http.Request) {
	errorMsg, code, err := func() (string, int, error) {
		if !r.config.EnableLoginHandler {
			return "attempt to login when login handler is disabled", http.StatusNotImplemented, errors.New("login handler disabled")
		}
		username := req.PostFormValue("username")
		password := req.PostFormValue("password")
		if username == "" || password == "" {
			return "request does not have both username and password", http.StatusBadRequest, errors.New("no credentials")
		}

		client, err := r.client.OAuthClient()
		if err != nil {
			return "unable to create the oauth client for user_credentials request", http.StatusInternalServerError, err
		}

		token, err := client.UserCredsToken(username, password)
		if err != nil {
			if strings.HasPrefix(err.Error(), oauth2.ErrorInvalidGrant) {
				return "invalid user credentials provided", http.StatusUnauthorized, err
			}
			return "unable to request the access token via grant_type 'password'", http.StatusInternalServerError, err
		}

		_, identity, err := parseToken(token.AccessToken)
		if err != nil {
			return "unable to decode the access token", http.StatusNotImplemented, err
		}

		r.dropAccessTokenCookie(req, w, token.AccessToken, time.Until(identity.ExpiresAt))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse{
			IDToken:      token.IDToken,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    token.Expires,
			Scope:        token.Scope,
		}); err != nil {
			return "", http.StatusInternalServerError, err
		}

		return "", http.StatusOK, nil
	}()
	if err != nil {
		r.log.Error(errorMsg,
			zap.String("client_ip", req.RemoteAddr),
			zap.Error(err))

		w.WriteHeader(code)
	}
}

// emptyHandler is responsible for doing nothing
func emptyHandler(w http.ResponseWriter, req *http.Request) {}

// logoutHandler performs a logout
//  - if it's just a access token, the cookie is deleted
//  - if the user has a refresh token, the token is invalidated by the provider
//  - optionally, the user can be redirected by to a url
func (r *oauthProxy) logoutHandler(w http.ResponseWriter, req *http.Request) {
	// the user can specify a url to redirect the back
	redirectURL := req.URL.Query().Get("redirect")

	user, err := r.getIdentity(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// step: can either use the id token or the refresh token
	identityToken := user.token.Encode()
	if refresh, _, err := r.retrieveRefreshToken(req, user); err == nil {
		identityToken = refresh
	}
	r.clearAllCookies(req, w)

	// step: check if the user has a state session and if so revoke it
	if r.useStore() {
		go func() {
			if err := r.DeleteRefreshToken(user.token); err != nil {
				r.log.Error("unable to remove the refresh token from store", zap.Error(err))
			}
		}()
	}

	// set the default revocation url
	revokeDefault := ""
	if r.idp.EndSessionEndpoint != nil {
		revokeDefault = r.idp.EndSessionEndpoint.String()
	}
	revocationURL := utils.DefaultTo(r.config.RevocationEndpoint, revokeDefault)

	if revocationURL != "" {
		client, err := r.client.OAuthClient()
		if err != nil {
			r.log.Error("unable to retrieve the openid client", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// step: add the authentication headers
		encodedID := url.QueryEscape(r.config.ClientID)
		encodedSecret := url.QueryEscape(r.config.ClientSecret)

		// step: construct the url for revocation
		request, err := http.NewRequest(http.MethodPost, revocationURL, bytes.NewBufferString(fmt.Sprintf("refresh_token=%s", identityToken)))
		if err != nil {
			r.log.Error("unable to construct the revocation request", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// step: add the authentication headers and content-type
		request.SetBasicAuth(encodedID, encodedSecret)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := client.HttpClient().Do(request)
		if err != nil {
			r.log.Error("unable to post to revocation endpoint", zap.Error(err))
			return
		}

		switch response.StatusCode {
		case http.StatusNoContent:
			r.log.Info("successfully logged out of the endpoint", zap.String("email", user.email))
		default:
			content, _ := ioutil.ReadAll(response.Body)
			r.log.Error("invalid response from revocation endpoint",
				zap.Int("status", response.StatusCode),
				zap.String("response", fmt.Sprintf("%s", content)))
		}
	}

	if redirectURL != "" {
		r.redirectToURL(redirectURL, w, req)
	}
}

// expirationHandler checks if the token has expired
func (r *oauthProxy) expirationHandler(w http.ResponseWriter, req *http.Request) {
	user, err := r.getIdentity(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if user.isExpired() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// tokenHandler display access token to screen
func (r *oauthProxy) tokenHandler(w http.ResponseWriter, req *http.Request) {
	user, err := r.getIdentity(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(user.token.Payload)
}

// healthHandler is a health check handler for the service
func (r *oauthProxy) healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set(constants.VersionHeader, constants.GetVersion())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

// debugHandler is responsible for providing the pprof
func (r *oauthProxy) debugHandler(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	switch req.Method {
	case http.MethodGet:
		switch name {
		case "heap":
			fallthrough
		case "goroutine":
			fallthrough
		case "block":
			fallthrough
		case "threadcreate":
			pprof.Handler(name).ServeHTTP(w, req)
		case "cmdline":
			pprof.Cmdline(w, req)
		case "profile":
			pprof.Profile(w, req)
		case "trace":
			pprof.Trace(w, req)
		case "symbol":
			pprof.Symbol(w, req)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPost:
		switch name {
		case "symbol":
			pprof.Symbol(w, req)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// proxyMetricsHandler forwards the request into the prometheus handler
func (r *oauthProxy) proxyMetricsHandler(w http.ResponseWriter, req *http.Request) {
	if r.config.LocalhostMetrics {
		if !net.ParseIP(utils.RealIP(req)).IsLoopback() {
			r.accessForbidden(w, req)
			return
		}
	}
	r.metricsHandler.ServeHTTP(w, req)
}

// retrieveRefreshToken retrieves the refresh token from store or cookie
func (r *oauthProxy) retrieveRefreshToken(req *http.Request, user *userContext) (token, encrypted string, err error) {
	switch r.useStore() {
	case true:
		token, err = r.GetRefreshToken(user.token)
	default:
		token, err = r.getRefreshTokenFromCookie(req)
	}
	if err != nil {
		return
	}

	encrypted = token
	token, err = utils.DecodeText(token, r.config.EncryptionKey)
	return
}

func methodNotAllowHandlder(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write(nil)
}

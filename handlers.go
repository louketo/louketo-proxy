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
	"bytes"
	"encoding/base64"
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

	"github.com/gambol99/go-oidc/oauth2"
	"github.com/labstack/echo"
	"go.uber.org/zap"
)

// getRedirectionURL returns the redirectionURL for the oauth flow
func (r *oauthProxy) getRedirectionURL(cx echo.Context) string {
	var redirect string
	switch r.config.RedirectionURL {
	case "":
		// need to determine the scheme, cx.Request.URL.Scheme doesn't have it, best way is to default
		// and then check for TLS
		scheme := "http"
		if !cx.IsTLS() {
			scheme = "https"
		}
		// @QUESTION: should I use the X-Forwarded-<header>?? ..
		redirect = fmt.Sprintf("%s://%s",
			defaultTo(cx.Request().Header.Get("X-Forwarded-Proto"), scheme),
			defaultTo(cx.Request().Header.Get("X-Forwarded-Host"), cx.Request().Host))
	default:
		redirect = r.config.RedirectionURL
	}

	return fmt.Sprintf("%s/oauth/callback", redirect)
}

// oauthHandler is required due to the fact the echo router does not run middleware if no handler
// is found for a group https://github.com/labstack/echo/issues/856
func (r *oauthProxy) oauthHandler(cx echo.Context) error {
	handler := fmt.Sprintf("/%s", strings.TrimLeft(cx.Param("name"), "/"))
	r.revokeProxy(cx)
	switch cx.Request().Method {
	case http.MethodGet:
		switch handler {
		case authorizationURL:
			return r.oauthAuthorizationHandler(cx)
		case callbackURL:
			return r.oauthCallbackHandler(cx)
		case expiredURL:
			return r.expirationHandler(cx)
		case healthURL:
			return r.healthHandler(cx)
		case logoutURL:
			return r.logoutHandler(cx)
		case tokenURL:
			return r.tokenHandler(cx)
		case metricsURL:
			if r.config.EnableMetrics {
				return r.proxyMetricsHandler(cx)
			}
		default:
			return cx.NoContent(http.StatusNotFound)
		}
	case http.MethodPost:
		switch handler {
		case loginURL:
			return r.loginHandler(cx)
		default:
			return cx.NoContent(http.StatusNotFound)
		}
	default:
		return cx.NoContent(http.StatusMethodNotAllowed)
	}

	return nil
}

// oauthAuthorizationHandler is responsible for performing the redirection to oauth provider
func (r *oauthProxy) oauthAuthorizationHandler(cx echo.Context) error {
	if r.config.SkipTokenVerification {
		return cx.NoContent(http.StatusNotAcceptable)
	}
	client, err := r.getOAuthClient(r.getRedirectionURL(cx))
	if err != nil {
		r.log.Error("failed to retrieve the oauth client for authorization", zap.Error(err))
		return cx.NoContent(http.StatusInternalServerError)
	}

	// step: set the access type of the session
	var accessType string
	if containedIn("offline", r.config.Scopes) {
		accessType = "offline"
	}

	authURL := client.AuthCodeURL(cx.QueryParam("state"), accessType, "")
	r.log.Debug("incoming authorization request from client address",
		zap.String("access_type", accessType),
		zap.String("auth_url", authURL),
		zap.String("client_ip", cx.RealIP()))

	// step: if we have a custom sign in page, lets display that
	if r.config.hasCustomSignInPage() {
		model := make(map[string]string)
		model["redirect"] = authURL

		return cx.Render(http.StatusOK, path.Base(r.config.SignInPage), mergeMaps(model, r.config.Tags))
	}

	return r.redirectToURL(authURL, cx)
}

// oauthCallbackHandler is responsible for handling the response from oauth service
func (r *oauthProxy) oauthCallbackHandler(cx echo.Context) error {
	if r.config.SkipTokenVerification {
		return cx.NoContent(http.StatusNotAcceptable)
	}
	// step: ensure we have a authorization code
	code := cx.QueryParam("code")
	if code == "" {
		return cx.NoContent(http.StatusBadRequest)
	}

	client, err := r.getOAuthClient(r.getRedirectionURL(cx))
	if err != nil {
		r.log.Error("unable to create a oauth2 client", zap.Error(err))
		return cx.NoContent(http.StatusInternalServerError)
	}

	resp, err := exchangeAuthenticationCode(client, code)
	if err != nil {
		r.log.Error("unable to exchange code for access token", zap.Error(err))
		return r.accessForbidden(cx)
	}

	// Flow: once we exchange the authorization code we parse the ID Token; we then check for a access token,
	// if a access token is present and we can decode it, we use that as the session token, otherwise we default
	// to the ID Token.
	token, identity, err := parseToken(resp.IDToken)
	if err != nil {
		r.log.Error("unable to parse id token for identity", zap.Error(err))
		return r.accessForbidden(cx)
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
		return r.accessForbidden(cx)
	}
	accessToken := token.Encode()

	// step: are we encrypting the access token?
	if r.config.EnableEncryptedToken {
		if accessToken, err = encodeText(accessToken, r.config.EncryptionKey); err != nil {
			r.log.Error("unable to encode the access token", zap.Error(err))
			return cx.NoContent(http.StatusInternalServerError)
		}
	}

	r.log.Info("issuing access token for user",
		zap.String("email", identity.Email),
		zap.String("expires", identity.ExpiresAt.Format(time.RFC3339)),
		zap.String("duration", time.Until(identity.ExpiresAt).String()))

	// step: does the response has a refresh token and we are NOT ignore refresh tokens?
	if r.config.EnableRefreshTokens && resp.RefreshToken != "" {
		var encrypted string
		encrypted, err = encodeText(resp.RefreshToken, r.config.EncryptionKey)
		if err != nil {
			r.log.Error("failed to encrypt the refresh token", zap.Error(err))
			return cx.NoContent(http.StatusInternalServerError)
		}
		// drop in the access token - cookie expiration = access token
		r.dropAccessTokenCookie(cx.Request(), cx.Response().Writer, accessToken, r.getAccessCookieExpiration(token, resp.RefreshToken))

		switch r.useStore() {
		case true:
			if err = r.StoreRefreshToken(token, encrypted); err != nil {
				r.log.Warn("failed to save the refresh token in the store", zap.Error(err))
			}
		default:
			// notes: not all idp refresh tokens are readable, google for example, so we attempt to decode into
			// a jwt and if possible extract the expiration, else we default to 10 days
			if _, ident, err := parseToken(resp.RefreshToken); err != nil {
				r.dropRefreshTokenCookie(cx.Request(), cx.Response().Writer, encrypted, time.Duration(240)*time.Hour)
			} else {
				r.dropRefreshTokenCookie(cx.Request(), cx.Response().Writer, encrypted, time.Until(ident.ExpiresAt))
			}
		}
	} else {
		r.dropAccessTokenCookie(cx.Request(), cx.Response().Writer, accessToken, time.Until(identity.ExpiresAt))
	}

	// step: decode the state variable
	state := "/"
	if cx.QueryParam("state") != "" {
		decoded, err := base64.StdEncoding.DecodeString(cx.QueryParam("state"))
		if err != nil {
			r.log.Warn("unable to decode the state parameter",
				zap.String("state", cx.QueryParam("state")),
				zap.Error(err))
		} else {
			state = string(decoded)
		}
	}

	return r.redirectToURL(state, cx)
}

// loginHandler provide's a generic endpoint for clients to perform a user_credentials login to the provider
func (r *oauthProxy) loginHandler(cx echo.Context) error {
	errorMsg, code, err := func() (string, int, error) {
		if !r.config.EnableLoginHandler {
			return "attempt to login when login handler is disabled", http.StatusNotImplemented, errors.New("login handler disabled")
		}
		username := cx.Request().PostFormValue("username")
		password := cx.Request().PostFormValue("password")
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

		r.dropAccessTokenCookie(cx.Request(), cx.Response().Writer, token.AccessToken, time.Until(identity.ExpiresAt))

		cx.JSON(http.StatusOK, tokenResponse{
			IDToken:      token.IDToken,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    token.Expires,
			Scope:        token.Scope,
		})

		return "", http.StatusOK, nil
	}()
	if err != nil {
		r.log.Error(errorMsg,
			zap.String("client_ip", cx.RealIP()),
			zap.Error(err))

		return cx.NoContent(code)
	}

	return nil
}

// emptyHandler is responsible for doing nothing
func emptyHandler(cx echo.Context) error {
	return nil
}

// logoutHandler performs a logout
//  - if it's just a access token, the cookie is deleted
//  - if the user has a refresh token, the token is invalidated by the provider
//  - optionally, the user can be redirected by to a url
func (r *oauthProxy) logoutHandler(cx echo.Context) error {
	// the user can specify a url to redirect the back
	redirectURL := cx.QueryParam("redirect")

	// step: drop the access token
	user, err := r.getIdentity(cx.Request())
	if err != nil {
		return cx.NoContent(http.StatusBadRequest)
	}
	// step: can either use the id token or the refresh token
	identityToken := user.token.Encode()
	if refresh, _, err := r.retrieveRefreshToken(cx.Request(), user); err == nil {
		identityToken = refresh
	}
	r.clearAllCookies(cx.Request(), cx.Response().Writer)

	// step: check if the user has a state session and if so revoke it
	if r.useStore() {
		go func() {
			if err := r.DeleteRefreshToken(user.token); err != nil {
				r.log.Error("unable to remove the refresh token from store", zap.Error(err))
			}
		}()
	}

	revocationURL := defaultTo(r.config.RevocationEndpoint, r.idp.EndSessionEndpoint.String())
	// step: do we have a revocation endpoint?
	if revocationURL != "" {
		client, err := r.client.OAuthClient()
		if err != nil {
			r.log.Error("unable to retrieve the openid client", zap.Error(err))
			return cx.NoContent(http.StatusInternalServerError)
		}

		// step: add the authentication headers
		// @TODO need to add the authenticated request to go-oidc
		encodedID := url.QueryEscape(r.config.ClientID)
		encodedSecret := url.QueryEscape(r.config.ClientSecret)

		// step: construct the url for revocation
		request, err := http.NewRequest(http.MethodPost, revocationURL,
			bytes.NewBufferString(fmt.Sprintf("refresh_token=%s", identityToken)))
		if err != nil {
			r.log.Error("unable to construct the revocation request", zap.Error(err))
			return cx.NoContent(http.StatusInternalServerError)
		}
		// step: add the authentication headers and content-type
		request.SetBasicAuth(encodedID, encodedSecret)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := client.HttpClient().Do(request)
		if err != nil {
			r.log.Error("unable to post to revocation endpoint", zap.Error(err))
			return nil
		}

		// step: check the response
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
	// step: should we redirect the user
	if redirectURL != "" {
		return r.redirectToURL(redirectURL, cx)
	}

	return cx.NoContent(http.StatusOK)
}

// expirationHandler checks if the token has expired
func (r *oauthProxy) expirationHandler(cx echo.Context) error {
	user, err := r.getIdentity(cx.Request())
	if err != nil {
		return cx.NoContent(http.StatusUnauthorized)
	}
	if user.isExpired() {
		return cx.NoContent(http.StatusUnauthorized)
	}

	return cx.NoContent(http.StatusOK)
}

// tokenHandler display access token to screen
func (r *oauthProxy) tokenHandler(cx echo.Context) error {
	user, err := r.getIdentity(cx.Request())
	if err != nil {
		return cx.String(http.StatusBadRequest, fmt.Sprintf("unable to retrieve session, error: %s", err))
	}
	cx.Response().Writer.Header().Set("Content-Type", "application/json")

	return cx.String(http.StatusOK, fmt.Sprintf("%s", user.token.Payload))
}

// healthHandler is a health check handler for the service
func (r *oauthProxy) healthHandler(cx echo.Context) error {
	cx.Response().Writer.Header().Set(versionHeader, getVersion())
	return cx.String(http.StatusOK, "OK\n")
}

// debugHandler is responsible for providing the pprof
func (r *oauthProxy) debugHandler(cx echo.Context) error {
	r.revokeProxy(cx)
	name := cx.Param("name")
	switch cx.Request().Method {
	case http.MethodGet:
		switch name {
		case "heap":
			fallthrough
		case "goroutine":
			fallthrough
		case "block":
			fallthrough
		case "threadcreate":
			pprof.Handler(name).ServeHTTP(cx.Response().Writer, cx.Request())
		case "cmdline":
			pprof.Cmdline(cx.Response().Writer, cx.Request())
		case "profile":
			pprof.Profile(cx.Response().Writer, cx.Request())
		case "trace":
			pprof.Trace(cx.Response().Writer, cx.Request())
		case "symbol":
			pprof.Symbol(cx.Response().Writer, cx.Request())
		default:
			cx.NoContent(http.StatusNotFound)
		}
	case http.MethodPost:
		switch name {
		case "symbol":
			pprof.Symbol(cx.Response().Writer, cx.Request())
		default:
			cx.NoContent(http.StatusNotFound)
		}
	}

	return nil
}

// proxyMetricsHandler forwards the request into the prometheus handler
func (r *oauthProxy) proxyMetricsHandler(cx echo.Context) error {
	if r.config.LocalhostMetrics {
		if !net.ParseIP(cx.RealIP()).IsLoopback() {
			return r.accessForbidden(cx)
		}
	}
	r.metricsHandler.ServeHTTP(cx.Response().Writer, cx.Request())

	return nil
}

// retrieveRefreshToken retrieves the refresh token from store or cookie
func (r *oauthProxy) retrieveRefreshToken(req *http.Request, user *userContext) (token, ecrypted string, err error) {
	switch r.useStore() {
	case true:
		token, err = r.GetRefreshToken(user.token)
	default:
		token, err = r.getRefreshTokenFromCookie(req)
	}
	if err != nil {
		return
	}

	ecrypted = token // returns encryped, avoid encoding twice
	token, err = decodeText(token, r.config.EncryptionKey)
	return
}

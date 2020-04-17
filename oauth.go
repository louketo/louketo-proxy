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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/jose"

	"github.com/coreos/go-oidc/oidc"
)

//FIXME remove constants in the future which hopefully won't be necessary in the next releases
const (
	GrantTypeAuthCode     = "authorization_code"
	GrantTypeUserCreds    = "password"
	GrantTypeRefreshToken = "refresh_token"
)

// newOAuth2Config returns a oauth2 config
func (r *oauthProxy) newOAuth2Config(redirectionURL string) *oauth2.Config {
	conf := &oauth2.Config{
		ClientID:     r.config.ClientID,
		ClientSecret: r.config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  r.idp.AuthEndpoint.String(),
			TokenURL: r.idp.TokenEndpoint.String(),
		},
		RedirectURL: redirectionURL,
		Scopes:      append(r.config.Scopes, oidc.DefaultScope...),
	}

	return conf
}

// verifyToken verify that the token in the user context is valid
func verifyToken(client *oidc.Client, token jose.JWT) error {
	if err := client.VerifyJWT(token); err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return ErrAccessTokenExpired
		}
		return err
	}

	return nil
}

// getRefreshedToken attempts to refresh the access token, returning the parsed token, optionally with a renewed
// refresh token and the time the access and refresh tokens expire
//
// NOTE: we may be able to extract the specific (non-standard) claim refresh_expires_in and refresh_expires
// from response.RawBody.
// When not available, keycloak provides us with the same (for now) expiry value for ID token.
func getRefreshedToken(conf *oauth2.Config, t string) (jose.JWT, string, time.Time, time.Duration, error) {
	tkn, err := conf.TokenSource(context.Background(), &oauth2.Token{RefreshToken: t}).Token()
	if err != nil {
		if strings.Contains(err.Error(), "refresh token has expired") {
			return jose.JWT{}, "", time.Time{}, time.Duration(0), ErrRefreshTokenExpired
		}
		return jose.JWT{}, "", time.Time{}, time.Duration(0), err
	}
	refreshExpiresIn := time.Until(tkn.Expiry)
	token, identity, err := parseToken(tkn.AccessToken)
	if err != nil {
		return jose.JWT{}, "", time.Time{}, time.Duration(0), err
	}

	return token, tkn.RefreshToken, identity.ExpiresAt, refreshExpiresIn, nil
}

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token
func exchangeAuthenticationCode(client *oauth2.Config, code string) (*oauth2.Token, error) {
	return getToken(client, GrantTypeAuthCode, code)
}

// getUserinfo is responsible for getting the userinfo from the IDPD
// use as an http.Client
// The goal is to replace completely go-oidc/http.Client by http.Client. The comment below
// disable the warnings from linter like:
// `client` can be `github.com/coreos/go-oidc/http.Client`
// nolint:interfacer
func getUserinfo(client *http.Client, endpoint string, token string) (jose.Claims, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authorizationHeader, fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("token not validate by userinfo endpoint")
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var claims jose.Claims
	if err := json.Unmarshal(content, &claims); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return claims, nil
}

// getToken retrieves a code from the provider, extracts and verified the token
func getToken(config *oauth2.Config, grantType, code string) (*oauth2.Token, error) {
	ctx := context.Background()
	start := time.Now()
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return token, err
	}
	taken := time.Since(start).Seconds()
	switch grantType {
	case GrantTypeAuthCode:
		oauthTokensMetric.WithLabelValues("exchange").Inc()
		oauthLatencyMetric.WithLabelValues("exchange").Observe(taken)
	case GrantTypeRefreshToken:
		oauthTokensMetric.WithLabelValues("renew").Inc()
		oauthLatencyMetric.WithLabelValues("renew").Observe(taken)
	}

	return token, err
}

// parseToken retrieves the user identity from the token
func parseToken(t string) (jose.JWT, *oidc.Identity, error) {
	token, err := jose.ParseJWT(t)
	if err != nil {
		return jose.JWT{}, nil, err
	}
	claims, err := token.Claims()
	if err != nil {
		return jose.JWT{}, nil, err
	}
	identity, err := oidc.IdentityFromClaims(claims)
	if err != nil {
		return jose.JWT{}, nil, err
	}

	return token, identity, nil
}

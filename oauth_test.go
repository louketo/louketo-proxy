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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/jose"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"
)

type fakeAuthServer struct {
	location   *url.URL
	key        jose.JWK
	signer     jose.Signer
	server     *httptest.Server
	expiration time.Duration
}

const fakePrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxMLIwi//YG6GPdYUPaV0PCXBEXjg2Xhf8/+NMB/1nt+wip4Z
rrAQf14PTCTlN4sbc2QGgRGtYikJBHQyfg/lCthrnasfdgL8c6SErr7Db524SqiD
m+/yKGI680LmBUIPkA0ikCJgb4cYVCiJ3HuYnFZUTsUAeK14SoXgcJdWulj0h6aP
iUIg5VrehuqAG+1RlK+GURgr9DbOmXJ/SYVKX/QArdBzjZ3BiQ1nxWWwBCLHfwv4
8bWxPJIbDDnUNl6LolpSJkxg4qlp+0I/xgEveK1n1CMEA0mHuXFHeekKO72GDKAk
h89C9qVF2GmpDfo8G0D3lFm2m3jFNyMQTWkSkwIDAQABAoIBADwhOrD9chHKNQQY
tD7SnV70OrhYNH7BJrGuWztlyO4wdgcmobqc263Q1OP0Mohy3oS5ALPY7x+cYsEV
sYiM2vYhhWG9tfOenf/JOzMb4SXvES7fqLiy71IgEtvcieb5dUAUg4eAue/bXTf6
24ahztWYHFOmKKq4eJZtq1U9KqfvlW1T4bg3mXV70huvfoMhYKwYryTOsQ5yiYCf
Yo4UGUBLfg3capIB5gxQdcqdDk+UTe9be7GQBj+3oziALb1nIhW7cpy0nw/r22A5
pv1FbRqND2VYKjZCQyUbxnjty5eDIW7fKBIh0Ez9yZHqz4KHb1u/KlFm31NGZpMU
Xs/WN+ECgYEA+kcAi7fTUjagqov5a4Y595ptu2gmU4Cxr+EBhMWadJ0g7enCXjTI
HAFEsVi2awbSRswjxdIG533SiKg8NIXThMntfbTm+Kw3LSb0/++Zyr7OuKJczKvQ
KfjAHvqsV8yJqy1gApYqVOeU4/jMLDs2sMY59/IQNkUVHNncZO09aa8CgYEAyUKG
BUyvxSim++YPk3OznBFZhqJqR75GYtWSu91BgZk/YmgYM4ht2u5q96AIRbJ664Ks
v93varNfqyKN1BN3JPLw8Ph8uX/7k9lMmECXoNp2Tm3A54zlsHyNOGOSvU7axvUg
PfIhpvRZKA0QQK3c1CZDghs94siJeBSIpuzCsl0CgYEA8Z28LCZiT3tHbn5FY4Wo
zp36k7L/VRvn7niVg71U2IGc+bHzoAjqqwaab2/KY9apCAop+t9BJRi2OJHZ1Ybg
5dAfg30ygh2YAvIaEj8YxL+iSGMOndS82Ng5eW7dFMH0ohnjF3wrD96mQdO+IHFl
4hDsg67f8dSNhlXYzGKwKCcCgYEAlAsrKprOcOkGbCU/L+fcJuFcSX0PUNbWT71q
wmZu2TYxOeH4a2/f3zuh06UUcLBpWvQ0vq4yfvqTVP+F9IqdCcDrG1at6IYMOSWP
AjABWYFZpTd2vt0V2EzGVMRqHHb014VYwjhqKLV1H9D8M5ew6R18ayg+zaNV+86e
9qsSTMECgYEA322XUN8yUBTTWBkXY7ipzTHSWkxMuj1Pa0gtBd6Qqqu3v7qI+jMZ
hlWS2akhJ+3e7f3+KCslG8YMItld4VvAK0eHKQbQM/onav/+/iiR6C2oRBm3OwqO
Ka0WPQGKjQJhZRtqDAT3sfnrEEUa34+MkXQeKFCu6Yi0dRFic4iqOYU=
-----END RSA PRIVATE KEY-----
`

type fakeDiscoveryResponse struct {
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint       string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// newFakeAuthServer simulates a oauth service
func newFakeAuthServer() *fakeAuthServer {
	// step: load the private key
	block, _ := pem.Decode([]byte(fakePrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse the private key, error: " + err.Error())
	}
	service := &fakeAuthServer{
		key: jose.JWK{
			ID:       "test-kid",
			Type:     "RSA",
			Alg:      "RS256",
			Use:      "sig",
			Exponent: privateKey.PublicKey.E,
			Modulus:  privateKey.PublicKey.N,
			Secret:   block.Bytes,
		},
		signer: jose.NewSignerRSA("test-kid", *privateKey),
	}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/auth/realms/hod-test/.well-known/openid-configuration", service.discoveryHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/certs", service.keysHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/auth", service.authHandler)
	r.Get("/auth/realms/hod-test/protocol/openid-connect/userinfo", service.userInfoHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/logout", service.logoutHandler)
	r.Post("/auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)

	service.server = httptest.NewServer(r)
	location, err := url.Parse(service.server.URL)
	if err != nil {
		panic("unable to create fake oauth service, error: " + err.Error())
	}
	service.location = location
	service.expiration = time.Duration(1) * time.Hour

	return service
}

func (r *fakeAuthServer) Close() {
	r.server.Close()
}

func (r *fakeAuthServer) getLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) getRevocationURL() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Scheme, r.location.Host)
}

func (r *fakeAuthServer) signToken(claims jose.Claims) (*jose.JWT, error) {
	return jose.NewSignedJWT(claims, r.signer)
}

func (r *fakeAuthServer) setTokenExpiration(tm time.Duration) *fakeAuthServer {
	r.expiration = tm
	return r
}

func (r *fakeAuthServer) discoveryHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, fakeDiscoveryResponse{
		AuthorizationEndpoint:            fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/auth", r.location.Host),
		EndSessionEndpoint:               fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Host),
		Issuer:                           fmt.Sprintf("http://%s/auth/realms/hod-test", r.location.Host),
		JwksURI:                          fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/certs", r.location.Host),
		RegistrationEndpoint:             fmt.Sprintf("http://%s/auth/realms/hod-test/clients-registrations/openid-connect", r.location.Host),
		TokenEndpoint:                    fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token", r.location.Host),
		TokenIntrospectionEndpoint:       fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token/introspect", r.location.Host),
		UserinfoEndpoint:                 fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/userinfo", r.location.Host),
		GrantTypesSupported:              []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ResponseModesSupported:           []string{"query", "fragment", "form_post"},
		ResponseTypesSupported:           []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		SubjectTypesSupported:            []string{"public"},
	})
}

func (r *fakeAuthServer) keysHandler(w http.ResponseWriter, req *http.Request) {
	renderJSON(http.StatusOK, w, req, jose.JWKSet{Keys: []jose.JWK{r.key}})
}

func (r *fakeAuthServer) authHandler(w http.ResponseWriter, req *http.Request) {
	state := req.URL.Query().Get("state")
	redirect := req.URL.Query().Get("redirect_uri")
	if redirect == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if state == "" {
		state = "/"
	}
	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, getRandomString(32))

	http.Redirect(w, req, redirectionURL, http.StatusSeeOther)
}

func (r *fakeAuthServer) logoutHandler(w http.ResponseWriter, req *http.Request) {
	if refreshToken := req.FormValue("refresh_token"); refreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (r *fakeAuthServer) userInfoHandler(w http.ResponseWriter, req *http.Request) {
	items := strings.Split(req.Header.Get("Authorization"), " ")
	if len(items) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	decoded, err := jose.ParseJWT(items[1])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, err := decoded.Claims()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	renderJSON(http.StatusOK, w, req, map[string]interface{}{
		"sub":                claims["sub"],
		"name":               claims["name"],
		"given_name":         claims["given_name"],
		"family_name":        claims["familty_name"],
		"preferred_username": claims["preferred_username"],
		"email":              claims["email"],
		"picture":            claims["picture"],
	})
}

func (r *fakeAuthServer) tokenHandler(w http.ResponseWriter, req *http.Request) {
	expires := time.Now().Add(r.expiration)
	unsigned := newTestToken(r.getLocation())
	unsigned.setExpiration(expires)

	// sign the token with the private key
	token, err := jose.NewSignedJWT(unsigned.claims, r.signer)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch req.FormValue("grant_type") {
	case GrantTypeUserCreds:
		username := req.FormValue("username")
		password := req.FormValue("password")
		if username == "" || password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if username == validUsername && password == validPassword {
			renderJSON(http.StatusOK, w, req, tokenResponse{
				IDToken:      token.Encode(),
				AccessToken:  token.Encode(),
				RefreshToken: token.Encode(),
				ExpiresIn:    float64(expires.UTC().Second()),
			})
			return
		}
		renderJSON(http.StatusUnauthorized, w, req, map[string]string{
			"error":             "invalid_grant",
			"error_description": "invalid user credentials",
		})
	case GrantTypeRefreshToken:
		fallthrough
	case GrantTypeAuthCode:
		renderJSON(http.StatusOK, w, req, tokenResponse{
			IDToken:      token.Encode(),
			AccessToken:  token.Encode(),
			RefreshToken: token.Encode(),
			ExpiresIn:    float64(expires.Second()),
		})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestGetUserinfo(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation()).getToken()
	tokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token.Encode()},
	)
	client := oauth2.NewClient(context.Background(), tokenSource)
	claims, err := getUserinfo(client, px.idp.UserInfoEndpoint.String(), token.Encode())
	assert.NoError(t, err)
	assert.NotEmpty(t, claims)
}

func TestTokenExpired(t *testing.T) {
	px, idp, _ := newTestProxyService(nil)
	token := newTestToken(idp.getLocation())
	cs := []struct {
		Expire time.Duration
		OK     bool
	}{
		{
			Expire: 1 * time.Hour,
			OK:     true,
		},
		{
			Expire: -5 * time.Hour,
		},
	}
	for i, x := range cs {
		token.setExpiration(time.Now().Add(x.Expire))
		signed, err := idp.signToken(token.claims)
		if err != nil {
			t.Errorf("case %d unable to sign the token, error: %s", i, err)
			continue
		}
		err = verifyToken(px.client, *signed)
		if x.OK && err != nil {
			t.Errorf("case %d, expected: %t got error: %s", i, x.OK, err)
		}
		if !x.OK && err == nil {
			t.Errorf("case %d, expected: %t got no error", i, x.OK)
		}
	}
}

func getRandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func renderJSON(code int, w http.ResponseWriter, req *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

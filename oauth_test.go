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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/gin-gonic/gin"
)

type fakeOAuthServer struct {
	sync.Mutex
	// the location of the service
	location *url.URL
	// the private key
	privateKey *rsa.PrivateKey
	// the jwk key
	key jose.JWK
	// the signer
	signer jose.Signer
	// the claims
	claims jose.Claims
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

//
// newFakeOAuthServer simulates a oauth service
//
func newFakeOAuthServer(t *testing.T) *fakeOAuthServer {
	// step: load the private key
	block, _ := pem.Decode([]byte(fakePrivateKey))
	// step: parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse the private key, error: %s", err)
	}

	service := &fakeOAuthServer{
		claims: jose.Claims{
			"jti":                "4ee75b8e-3ee6-4382-92d4-3390b4b4937b",
			"exp":                int(time.Now().Add(time.Duration(10) * time.Hour).Unix()),
			"nbf":                0,
			"iat":                float64(1450372669),
			"aud":                "test",
			"sub":                "1e11e539-8256-4b3b-bda8-cc0d56cddb48",
			"typ":                "Bearer",
			"azp":                "clientid",
			"session_state":      "98f4c3d2-1b8c-4932-b8c4-92ec0ea7e195",
			"client_session":     "f0105893-369a-46bc-9661-ad8c747b1a69",
			"email":              "gambol99@gmail.com",
			"name":               "Rohith Jayawardene",
			"family_name":        "Jayawardene",
			"preferred_username": "rjayawardene",
			"given_name":         "Rohith",
		},
		privateKey: privateKey,
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

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("auth/realms/hod-test/.well-known/openid-configuration", service.discoveryHandler)
	r.GET("auth/realms/hod-test/protocol/openid-connect/certs", service.keysHandler)
	r.GET("auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	r.POST("auth/realms/hod-test/protocol/openid-connect/token", service.tokenHandler)
	r.GET("auth/realms/hod-test/protocol/openid-connect/auth", service.authHandler)

	location, err := url.Parse(httptest.NewServer(r).URL)
	if err != nil {
		t.Fatalf("unable to create fake oauth service, error: %s", err)
	}
	service.location = location
	service.claims["iss"] = service.getLocation()

	return service
}

func (r *fakeOAuthServer) getLocation() string {
	return fmt.Sprintf("%s://%s/auth/realms/hod-test", r.location.Scheme, r.location.Host)
}

func (r *fakeOAuthServer) setUserRealmRoles(roles []string) *fakeOAuthServer {
	r.claims["realm_access"] = map[string]interface{}{
		"roles": roles,
	}
	return r
}

func (r *fakeOAuthServer) setUserExpiration(duration time.Duration) *fakeOAuthServer {
	r.claims["exp"] = time.Now().Add(duration).Second()
	return r
}

func (r *fakeOAuthServer) discoveryHandler(cx *gin.Context) {
	cx.JSON(http.StatusOK, fakeDiscoveryResponse{
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		Issuer:                     fmt.Sprintf("http://%s/auth/realms/hod-test", r.location.Host),
		AuthorizationEndpoint:      fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/auth", r.location.Host),
		TokenEndpoint:              fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token", r.location.Host),
		RegistrationEndpoint:       fmt.Sprintf("http://%s/auth/realms/hod-test/clients-registrations/openid-connect", r.location.Host),
		TokenIntrospectionEndpoint: fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/token/introspect", r.location.Host),
		UserinfoEndpoint:           fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/userinfo", r.location.Host),
		EndSessionEndpoint:         fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/logout", r.location.Host),
		JwksURI:                    fmt.Sprintf("http://%s/auth/realms/hod-test/protocol/openid-connect/certs", r.location.Host),
		GrantTypesSupported:        []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
		ResponseModesSupported:     []string{"query", "fragment", "form_post"},
		ResponseTypesSupported:     []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		SubjectTypesSupported:      []string{"public"},
	})
}

func (r *fakeOAuthServer) keysHandler(cx *gin.Context) {
	cx.JSON(http.StatusOK, jose.JWKSet{Keys: []jose.JWK{r.key}})
}

func (r *fakeOAuthServer) authHandler(cx *gin.Context) {
	state := cx.Query("state")
	redirect := cx.Query("redirect_uri")

	if redirect == "" {
		cx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if state == "" {
		state = "/"
	}
	// step: generate a random authentication code
	redirectionURL := fmt.Sprintf("%s?state=%s&code=%s", redirect, state, getRandomString(32))

	cx.Redirect(http.StatusTemporaryRedirect, redirectionURL)
}

func (r *fakeOAuthServer) tokenHandler(cx *gin.Context) {
	expiration := time.Now().Add(time.Duration(1) * time.Hour)

	token, err := jose.NewSignedJWT(r.claims, r.signer)
	if err != nil {
		cx.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	switch cx.PostForm("grant_type") {
	case oauth2.GrantTypeUserCreds:
		username := cx.PostForm("username")
		password := cx.PostForm("password")
		if username == "" || password == "" {
			cx.AbortWithStatus(http.StatusBadRequest)
			return
		}
		cx.JSON(http.StatusOK, tokenResponse{
			IDToken:      token.Encode(),
			AccessToken:  token.Encode(),
			RefreshToken: token.Encode(),
			ExpiresIn:    expiration.Second(),
		})
	case oauth2.GrantTypeAuthCode:
		cx.JSON(http.StatusOK, tokenResponse{
			IDToken:      token.Encode(),
			AccessToken:  token.Encode(),
			RefreshToken: token.Encode(),
			ExpiresIn:    expiration.Second(),
		})
	default:
		fmt.Println("dsdsd")
		cx.AbortWithStatus(http.StatusBadRequest)
	}
}

func getRandomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

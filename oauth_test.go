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
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeOAuthServer struct {
}

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

type fakeKeysResponse struct {
	Keys []fakeKeyResponse `json:"keys"`
}

type fakeKeyResponse struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

const (
	fakePublicKey = "ibGNjo_opyEGbeDP3cctILhSW-sGKtG67hCZXxvHx-wd6n2KUNIPgs2yn0nH8XFJmrMbxnCe5-FMbHth-TKZiEhm-3EBadc1qgkfnpinfpxCVqHHaF8mFLC5-k3JsINIR0FAmPN9trxryI_npHzkDyfMbml2h21AHboZ3IJON3SbS2S1HaKR5b58ER4cl669nest5ixaOQCAgWIGoO7mXx7pR1PX0VEdLMg498jZkSCcCbAty4wBtTlmyLKyLF5iYRJPgL1lYxGCUZd5VlfPVr0efLf1MLtQ4rCjXmjPMwWTlU0rsEIFh_rrLKAs0AdUYwXGAslnYDBACiR8GNrb7Q"

	oauthPublicKey   = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAibGNjo/opyEGbeDP3cctILhSW+sGKtG67hCZXxvHx+wd6n2KUNIPgs2yn0nH8XFJmrMbxnCe5+FMbHth+TKZiEhm+3EBadc1qgkfnpinfpxCVqHHaF8mFLC5+k3JsINIR0FAmPN9trxryI/npHzkDyfMbml2h21AHboZ3IJON3SbS2S1HaKR5b58ER4cl669nest5ixaOQCAgWIGoO7mXx7pR1PX0VEdLMg498jZkSCcCbAty4wBtTlmyLKyLF5iYRJPgL1lYxGCUZd5VlfPVr0efLf1MLtQ4rCjXmjPMwWTlU0rsEIFh/rrLKAs0AdUYwXGAslnYDBACiR8GNrb7QIDAQAB"
	oauthPrivateKey  = "MIIEowIBAAKCAQEAibGNjo/opyEGbeDP3cctILhSW+sGKtG67hCZXxvHx+wd6n2KUNIPgs2yn0nH8XFJmrMbxnCe5+FMbHth+TKZiEhm+3EBadc1qgkfnpinfpxCVqHHaF8mFLC5+k3JsINIR0FAmPN9trxryI/npHzkDyfMbml2h21AHboZ3IJON3SbS2S1HaKR5b58ER4cl669nest5ixaOQCAgWIGoO7mXx7pR1PX0VEdLMg498jZkSCcCbAty4wBtTlmyLKyLF5iYRJPgL1lYxGCUZd5VlfPVr0efLf1MLtQ4rCjXmjPMwWTlU0rsEIFh/rrLKAs0AdUYwXGAslnYDBACiR8GNrb7QIDAQABAoIBAGtfMlSmMbUKErpiIZX+uFkYgti8p92CGLOF7CN3RU3H+PgfF1m4xHGqt4xw+2JyhgQFgTY4IiIN1QuPFzI82+6jDvMqBwEi2e0TGj4RKiOX9D8b/qSL9eUSfqQKPqnPZfBymM3sqe5yddY7KVZiMXEEBu1efhhTADluIraKQjYJKgQd0P3CgfqhuUWgCqGjPwIg0BkzXofR0bjdrq8d0ul8JLnT+9ho/x8rahEN/LTHHLIwb6IYUj8X10tDZWPDk2NE5wRIy18peSXYNTeGhY1ThF75ZOAH5c1qgi0ObE+dUSqzwcDWqNDPxFvg2x67KbcMaTO6u87/mGJfuO2ekz0CgYEAwpR+tZdafTzR+MLGg55mxsfVjAWGNxp0AMwWZVTpPx1I+VgdLsMkUY8LpY2Zt8l2yInIGEzYRBNFYPrM73bW5v0bleGl60I6j3KA/Ic6RUaweycbQgMxob5PCWrMm94Jib1bGAxNU1m0Jp9rzxGUzWw3TpSw6LHNLqokwMCKG/cCgYEAtSg1oqeCvvCrIdA6AulzzWR6x2Re/Iv8MYJ5X0fNPRBHSVhwsdb2nLfjMPmLesBOPm55O/LZDFtL8unpOUc+qT8QWKAjvI0/HtYf2sec3sP/dxCYYK18grK1cvD/UAUfiljM0gAsxZRT77VbpOIMCOi9YjHoyeRgCQtxB9CuZjsCgYEAsLNfehLvpwmjeK+QzRf9J4l0AQtHPiU0sUClGfKJOrqieWUuYzftdG9d2UMFFGTNDQIqhv7J6tBBUfeQQep+8BdshKj9Hu7u9TO7tRgsr5qpS71QwJrb6JFFfzzQgL+bk800u1r4obe1pNljcxD5O6+JbkATg81rknQKmkx/XzMCgYARnyqwesjuF+0dqeqqs9jO5vJGiQ3wVRGgI0f5K7vcL8Qvb0nvErEEh6Ky9eNKeoBh9E8YtMPGPu9BXt2P8801m2vUoyc2xSqZrkyE9Jve04P7KgMYjGerMwURfD3po8XwqDisSNYSFh6gF60ledOf3jvl3GL/mJZ66sEA+JyuVwKBgGwef1FWkDTeft6VFo2obHCh8Fc8rsV2rQ0twgmA00nmuckKr5MQgyMiz2YYWanmOS18xLgl7FzvyX56clj1MvRl9xnwhSudtE4fxg6R4rzwf3jaWtAkXEHet+mqVRJgI9m5Bn8E7nVVmjgRlogZsgYq2pF3nL1sgl3ti7gOVVL6"
	oauthCertificate = "MIICnzCCAYcCBgFUPZAJhjANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhob2QtdGVzdDAeFw0xNjA0MjIxMDQwMzBaFw0yNjA0MjIxMDQyMTBaMBMxETAPBgNVBAMMCGhvZC10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAibGNjo/opyEGbeDP3cctILhSW+sGKtG67hCZXxvHx+wd6n2KUNIPgs2yn0nH8XFJmrMbxnCe5+FMbHth+TKZiEhm+3EBadc1qgkfnpinfpxCVqHHaF8mFLC5+k3JsINIR0FAmPN9trxryI/npHzkDyfMbml2h21AHboZ3IJON3SbS2S1HaKR5b58ER4cl669nest5ixaOQCAgWIGoO7mXx7pR1PX0VEdLMg498jZkSCcCbAty4wBtTlmyLKyLF5iYRJPgL1lYxGCUZd5VlfPVr0efLf1MLtQ4rCjXmjPMwWTlU0rsEIFh/rrLKAs0AdUYwXGAslnYDBACiR8GNrb7QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBFd9T/1s769tGhOMtUspP2tChKy5OWF50HkRVLny1nt12JeQUvuVSD3l7vN17hFRpMm1ktjVCTxBk5PRfPtpOcMCG2zgYbB73hIRYZaKG5X6/r2y3TllZ2UkZh0ndL+jrn1L4I2zxB5OAi3CDTxiFtjcEShAC9smjp04Omxwat53k8IxJLRgnpuC/TMbxUPHLNjuOHLLFeSN7095SuD+qzx0H7fT4sqW3+mAr7Q/kl2yq4vMXfLHt5KkOm7O5px5mRoGS4Asbkw5MQMgP618uQ9k7EQZx37jF2ol4Z7uLQWscePdWA66ajbxAtybCesNPa4uUrb1YVdx6MikWyZ0i7"
)

func newFakeOAuthServer(t *testing.T) {
	s := new(fakeOAuthServer)
	r := gin.New()
	r.GET("/auth/realms/hod-test/.well-known/openid-configuration", s.discoveryHandler)
	r.GET("/auth/realms/hod-test/protocol/openid-connect/certs", s.keysHandler)
	r.POST("/auth/realms/hod-test/protocol/openid-connect/token", s.tokenHandler)
	r.POST("/auth/realms/hod-test/protocol/openid-connect/auth", s.authHandler)

	if err := r.Run("127.0.0.1:8080"); err != nil {
		t.Fatalf("failed to start the fake oauth service, error: %s", err)
	}
}

func (r fakeOAuthServer) discoveryHandler(cx *gin.Context) {
	cx.JSON(http.StatusOK, fakeDiscoveryResponse{
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		Issuer:                     "http://127.0.0.1:8080/auth/realms/hod-test",
		AuthorizationEndpoint:      "http://127.0.0.1:8080/auth/realms/hod-test/protocol/openid-connect/auth",
		TokenEndpoint:              "http://127.0.0.1:8080/auth/realms/hod-test/protocol/openid-connect/token",
		RegistrationEndpoint:       "http://127.0.0.1:8080/auth/realms/hod-test/clients-registrations/openid-connect",
		TokenIntrospectionEndpoint: "http://127.0.0.1:8080/auth/realms/hod-test/protocol/openid-connect/token/introspect",
		UserinfoEndpoint:           "http://127.0.0.1:8080/auth/realms/hod-test/protocol/openid-connect/userinfo",
		EndSessionEndpoint:         "http://127.0.0.1:8080/auth/realms/hod-test/protocol/openid-connect/logout",
		JwksURI:                    "http://127.0.0.1:8080/auth/realms/hod-test/protocol/openid-connect/certs",
		GrantTypesSupported:        []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
		ResponseModesSupported:     []string{"query", "fragment", "form_post"},
		ResponseTypesSupported:     []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		SubjectTypesSupported:      []string{"public"},
	})
}

func (r fakeOAuthServer) keysHandler(cx *gin.Context) {
	cx.JSON(http.StatusOK, fakeKeysResponse{
		Keys: []fakeKeyResponse{
			{
				Kid: "ing3Hnuj0ciqrHCOxt__-B53jzXcdD1n1iKbX3GsD9s",
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				N:   fakePublicKey,
				E:   "AQAB",
			},
		},
	})
}

func (r fakeOAuthServer) authHandler(cx *gin.Context) {

}

func (r fakeOAuthServer) tokenHandler(cx *gin.Context) {

}

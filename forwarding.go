//+build !noforwarding

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
	"fmt"
	"io/ioutil"
	httplog "log"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/elazarl/goproxy"
	"github.com/oneconcern/keycloak-gatekeeper/version"
	"go.uber.org/zap"
)

func (r *Config) isForwardingValid() error {
	if r.ClientID == "" {
		return errors.New("you have not specified the client id")
	}
	if err := r.isDiscoveryValid(); err != nil {
		return err
	}
	if r.ForwardingUsername == "" {
		return errors.New("no forwarding username")
	}
	if r.ForwardingPassword == "" {
		return errors.New("no forwarding password")
	}
	if r.TLSCertificate != "" {
		return errors.New("you don't need to specify a tls-certificate, use tls-ca-certificate instead")
	}
	if r.TLSPrivateKey != "" {
		return errors.New("you don't need to specify the tls-private-key, use tls-ca-key instead")
	}
	return nil
}

// createForwardingProxy creates a forwarding proxy
func (r *oauthProxy) createForwardingProxy() error {
	r.log.Info("enabling forward signing mode, listening on", zap.String("interface", r.config.Listen))

	if r.config.SkipUpstreamTLSVerify {
		r.log.Warn("tls verification switched off. In forward signing mode it's recommended you verify! (--skip-upstream-tls-verify=false)")
	}
	if err := r.createProxy(); err != nil {
		return err
	}
	forwardingHandler := r.forwardProxyHandler()

	// set the http handler
	proxy := r.upstream.(*goproxy.ProxyHttpServer)
	r.router = proxy

	// setup the tls configuration
	if r.config.TLSCaCertificate != "" && r.config.TLSCaPrivateKey != "" {
		ca, err := loadCA(r.config.TLSCaCertificate, r.config.TLSCaPrivateKey)
		if err != nil {
			return fmt.Errorf("unable to load certificate authority, error: %s", err)
		}

		// implement the goproxy connect method
		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectMitm,
					TLSConfig: goproxy.TLSConfigFromCA(ca), // NOTE(fredbi): the default proxy config in github/elazarl/goproxy disables TLS verify
				}, host
			},
		)
	} else {
		// use the default certificate provided by goproxy
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// @NOTES, somewhat annoying but goproxy hands back a nil response on proxy client errors
		if resp != nil && r.config.EnableLogging {
			start := ctx.UserData.(time.Time)
			latency := time.Since(start)
			latencyMetric.Observe(latency.Seconds())
			r.log.Info("client request",
				zap.String("method", resp.Request.Method),
				zap.String("path", resp.Request.URL.Path),
				zap.Int("status", resp.StatusCode),
				zap.Int64("bytes", resp.ContentLength),
				zap.String("host", resp.Request.Host),
				zap.String("path", resp.Request.URL.Path),
				zap.String("latency", latency.String()))
		}

		return resp
	})
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.UserData = time.Now()
		forwardingHandler(req, ctx.Resp)
		return req, ctx.Resp
	})

	return nil
}

// forwardProxyHandler is responsible for signing outbound requests
func (r *oauthProxy) forwardProxyHandler() func(*http.Request, *http.Response) {
	client, err := r.client.OAuthClient()
	if err != nil {
		r.log.Fatal("failed to create oauth client", zap.Error(err))
	}
	// the loop state
	var state struct {
		// the access token
		token jose.JWT
		// the refresh token if any
		refresh string
		// the identity of the user
		identity *oidc.Identity
		// the expiry time of the access token
		expiration time.Time
		// whether we need to login
		login bool
		// whether we should wait for expiration
		wait bool
	}
	state.login = true

	// create a routine to refresh the access tokens or login on expiration
	go func() {
		for {
			state.wait = false

			// step: do we have a access token
			if state.login {
				r.log.Info("requesting access token for user",
					zap.String("username", r.config.ForwardingUsername))

				// step: login into the service
				resp, err := client.UserCredsToken(r.config.ForwardingUsername, r.config.ForwardingPassword)
				if err != nil {
					r.log.Error("failed to login to authentication service", zap.Error(err))
					// step: back-off and reschedule
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: parse the token
				token, identity, err := parseToken(resp.AccessToken)
				if err != nil {
					r.log.Error("failed to parse the access token", zap.Error(err))
					// step: we should probably hope and reschedule here
					<-time.After(time.Duration(5) * time.Second)
					continue
				}

				// step: update the loop state
				state.token = token
				state.identity = identity
				state.expiration = identity.ExpiresAt
				state.wait = true
				state.login = false
				state.refresh = resp.RefreshToken

				r.log.Info("successfully retrieved access token for subject",
					zap.String("subject", state.identity.ID),
					zap.String("email", state.identity.Email),
					zap.String("expires", state.expiration.Format(time.RFC3339)))

			} else {
				r.log.Info("access token is about to expiry",
					zap.String("subject", state.identity.ID),
					zap.String("email", state.identity.Email))

				// step: if we a have a refresh token, we need to login again
				if state.refresh != "" {
					r.log.Info("attempting to refresh the access token",
						zap.String("subject", state.identity.ID),
						zap.String("email", state.identity.Email),
						zap.String("expires", state.expiration.Format(time.RFC3339)))

					// step: attempt to refresh the access
					token, newRefreshToken, expiration, _, err := getRefreshedToken(r.client, state.refresh)
					if err != nil {
						state.login = true
						switch err {
						case ErrRefreshTokenExpired:
							r.log.Warn("the refresh token has expired, need to login again",
								zap.String("subject", state.identity.ID),
								zap.String("email", state.identity.Email))
						default:
							r.log.Error("failed to refresh the access token", zap.Error(err))
						}
						continue
					}

					// step: update the state
					state.token = token
					state.expiration = expiration
					state.wait = true
					state.login = false
					if newRefreshToken != "" {
						state.refresh = newRefreshToken
					}

					// step: add some debugging
					r.log.Info("successfully refreshed the access token",
						zap.String("subject", state.identity.ID),
						zap.String("email", state.identity.Email),
						zap.String("expires", state.expiration.Format(time.RFC3339)))

				} else {
					r.log.Info("session does not support refresh token, acquiring new token",
						zap.String("subject", state.identity.ID),
						zap.String("email", state.identity.Email))

					// we don't have a refresh token, we must perform a login again
					state.wait = false
					state.login = true
				}
			}

			// wait for an expiration to come close
			if state.wait {
				// set the expiration of the access token within a random 85% of actual expiration
				duration := getWithin(state.expiration, 0.85)
				r.log.Info("waiting for expiration of access token",
					zap.String("token_expiration", state.expiration.Format(time.RFC3339)),
					zap.String("renewal_duration", duration.String()))

				<-time.After(duration)
			}
		}
	}()

	return func(req *http.Request, resp *http.Response) {
		hostname := req.Host
		req.URL.Host = hostname
		// is the host being signed?
		if len(r.config.ForwardingDomains) == 0 || containsSubString(hostname, r.config.ForwardingDomains) {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", state.token.Encode()))
			req.Header.Set("X-Forwarded-Agent", version.Prog)
		}
	}
}

// createProxy creates a reverse http proxy client to the upstream
func (r *oauthProxy) createProxy() error {
	dialer := (&net.Dialer{
		KeepAlive: r.config.UpstreamKeepaliveTimeout,
		Timeout:   r.config.UpstreamTimeout,
	}).Dial

	tlsConfig, err := r.buildProxyTLSConfig()
	if err != nil {
		return err
	}

	// create the forwarding proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.KeepDestinationHeaders = true
	proxy.Logger = httplog.New(ioutil.Discard, "", 0)
	r.upstream = proxy

	// update the tls configuration of the reverse proxy
	r.upstream.(*goproxy.ProxyHttpServer).Tr = &http.Transport{
		Dial:                  dialer,
		DisableKeepAlives:     !r.config.UpstreamKeepalives,
		ExpectContinueTimeout: r.config.UpstreamExpectContinueTimeout,
		ResponseHeaderTimeout: r.config.UpstreamResponseHeaderTimeout,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   r.config.UpstreamTLSHandshakeTimeout,
		MaxIdleConns:          r.config.MaxIdleConns,
		MaxIdleConnsPerHost:   r.config.MaxIdleConnsPerHost,
	}

	return nil
}

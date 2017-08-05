/*
Copyright 2017 All rights reserved.
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

package letsencrypt

import (
	"context"
	"crypto/tls"
	"net/url"

	"github.com/gambol99/keycloak-proxy/pkg/api"
	"github.com/gambol99/keycloak-proxy/pkg/certs"
	"github.com/gambol99/keycloak-proxy/pkg/errors"

	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
)

type provider struct {
	manager *autocert.Manager
	config  *api.Config
}

// New returns a letsencrypt provider
func New(c *api.Config, log *zap.Logger) (certs.Provider, error) {
	p := &provider{
		config: c,
		manager: &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(c.LetsEncryptCacheDir),
		},
	}
	p.manager.HostPolicy = p.enforceHostPolicy

	return p, nil
}

// enforceHostPolicy is responsible for the hostname policy
func (p *provider) enforceHostPolicy(_ context.Context, hostname string) error {
	if len(p.hostnames()) > 0 {
		found := false
		for _, h := range p.hostnames() {
			found = found || (h == hostname)
		}
		if !found {
			return errors.ErrHostNotConfigured
		}
	} else if p.redirectionURL() != "" {
		u, err := url.Parse(p.redirectionURL())
		if err != nil {
			return err
		}
		if u.Host != hostname {
			return errors.ErrHostNotConfigured
		}
	}

	return nil
}

// GetCertificate just wraps the letsencrypt method
func (p *provider) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.manager.GetCertificate(h)
}

// hostnames returns a list of hostnames from the config
func (p *provider) hostnames() []string {
	return p.config.Hostnames
}

// redirectionURL returns the redirectionURL from config
func (p *provider) redirectionURL() string {
	return p.config.RedirectionURL
}

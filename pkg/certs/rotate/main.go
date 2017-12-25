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

package rotate

import (
	"crypto/tls"
	"fmt"
	"path"
	"sync"

	"github.com/gambol99/keycloak-proxy/pkg/api"
	"github.com/gambol99/keycloak-proxy/pkg/certs"
	"github.com/gambol99/keycloak-proxy/pkg/utils"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type provider struct {
	sync.RWMutex
	config      *api.Config
	certificate tls.Certificate
	log         *zap.Logger
}

// New creates a new rotate provider
func New(c *api.Config, log *zap.Logger) (certs.Provider, error) {
	certificate, err := tls.LoadX509KeyPair(c.TLSCertificate, c.TLSPrivateKey)
	if err != nil {
		return nil, err
	}
	svc := &provider{
		certificate: certificate,
		config:      c,
		log:         log,
	}
	if err := svc.watch(); err != nil {
		return nil, err
	}

	return svc, nil
}

// watch is responsible for adding a file notification and watch on the files for changes
func (p *provider) watch() error {
	p.log.Info("adding a file watch on the tls certificates",
		zap.String("certificate", p.tlsCertificate()),
		zap.String("private_key", p.tlsPrivateKey()))

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	// add the files to the watch list
	for _, x := range []string{p.tlsCertificate(), p.tlsPrivateKey()} {
		if err := watcher.Add(path.Dir(x)); err != nil {
			return fmt.Errorf("unable to add watch on directory: %s, error: %s", path.Dir(x), err)
		}
	}

	// step: watching for events
	filewatchPaths := []string{p.tlsCertificate(), p.tlsPrivateKey()}
	go func() {
		p.log.Info("starting to watch changes to the tls certificate files")
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Write == fsnotify.Write {
					// step: does the change effect our files?
					if !utils.ContainedIn(event.Name, filewatchPaths) {
						continue
					}
					// step: reload the certificate
					certificate, err := tls.LoadX509KeyPair(p.tlsCertificate(), p.tlsPrivateKey())
					if err != nil {
						p.log.Error("unable to load the updated certificate",
							zap.String("filename", event.Name),
							zap.Error(err))
					}
					p.storeCertificate(certificate)
					p.log.Info("replacing the server certifacte with updated version")
				}
			case err := <-watcher.Errors:
				p.log.Error("recieved an error from the file watcher", zap.Error(err))
			}
		}
	}()

	return nil
}

// storeCertificate provides entrypoint to update the certificate
func (p *provider) storeCertificate(certifacte tls.Certificate) error {
	p.Lock()
	defer p.Unlock()
	p.certificate = certifacte

	return nil
}

// GetCertificate is responsible for retrieving
func (p *provider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.RLock()
	defer p.RUnlock()

	return &p.certificate, nil
}

func (p *provider) tlsCertificate() string {
	return p.config.TLSCertificate
}

func (p *provider) tlsPrivateKey() string {
	return p.config.TLSPrivateKey
}

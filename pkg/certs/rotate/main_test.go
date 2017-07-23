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
	"testing"

	"github.com/gambol99/keycloak-proxy/pkg/api"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	testCertificateFile = "../../../tests/proxy.pem"
	testPrivateKeyFile  = "../../../tests/proxy-key.pem"
)

func newTestCertificateRotator(t *testing.T) *certificationRotation {
	p, err := New(&api.Config{TLSCertificate: testCertificateFile, TLSPrivateKey: testPrivateKeyFile}, zap.NewNop())
	c := p.(*certificationRotation)
	assert.NotNil(t, c)
	assert.Equal(t, testCertificateFile, c.certificateFile)
	assert.Equal(t, testPrivateKeyFile, c.privateKeyFile)
	if !assert.NoError(t, err) {
		t.Fatalf("unable to create the certificate rotator, error: %s", err)
	}

	return c
}

func TestNewCeritifacteRotatorFailure(t *testing.T) {
	c, err := New(&api.Config{}, zap.NewNop())
	assert.Nil(t, c)
	assert.Error(t, err)
}

func TestGetCertificate(t *testing.T) {
	c := newTestCertificateRotator(t)
	assert.NotEmpty(t, c.certificate)
	crt, err := c.GetCertificate(nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, crt)
}

func TestLoadCertificate(t *testing.T) {
	c := newTestCertificateRotator(t)
	assert.NotEmpty(t, c.certificate)
	c.storeCertificate(tls.Certificate{})
	crt, err := c.GetCertificate(nil)
	assert.NoError(t, err)
	assert.Equal(t, &tls.Certificate{}, crt)
}

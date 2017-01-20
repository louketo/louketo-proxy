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

	"github.com/go-resty/resty"
	"github.com/stretchr/testify/assert"
)

func TestRedirectToAuthorizationUnauthorized(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.config.SkipTokenVerification = false
	p.config.NoRedirects = true

	resp, err := resty.DefaultClient.R().Get(svc + "/admin")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode())
}

func TestRedirectToAuthorization(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.config.SkipTokenVerification = false
	p.config.NoRedirects = false

	resp, _ := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy()).R().Get(svc + "/admin")
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode())
}

func TestRedirectToAuthorizationSkipToken(t *testing.T) {
	p, _, svc := newTestProxyService(nil)
	p.config.SkipTokenVerification = true

	resp, _ := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy()).R().Get(svc + "/admin")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode())
}

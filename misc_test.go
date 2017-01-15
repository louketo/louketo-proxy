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

	"github.com/stretchr/testify/assert"
)

func TestRedirectToAuthorizationUnauthorized(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)
	p.config.SkipTokenVerification = false
	p.config.NoRedirects = true

	p.redirectToAuthorization(context)
	assert.Equal(t, http.StatusUnauthorized, context.Writer.Status())
}

func TestRedirectToAuthorization(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	p.config.SkipTokenVerification = false
	p.redirectToAuthorization(context)
	assert.Equal(t, http.StatusTemporaryRedirect, context.Writer.Status())
}

func TestRedirectToAuthorizationSkipToken(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	p.config.SkipTokenVerification = true
	p.redirectToAuthorization(context)
	assert.Equal(t, http.StatusForbidden, context.Writer.Status())
}

func TestRedirectURL(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	if p.redirectToURL("http://127.0.0.1", context); context.Writer.Status() != http.StatusTemporaryRedirect {
		t.Error("we should have received a redirect")
	}

	if !context.IsAborted() {
		t.Error("the context should have been aborted")
	}
}

func TestAccessForbidden(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	p, _, _ := newTestProxyService(nil)

	p.config.SkipTokenVerification = false
	if p.accessForbidden(context); context.Writer.Status() != http.StatusForbidden {
		t.Error("we should have received a forbidden access")
	}

	p.config.SkipTokenVerification = true
	if p.accessForbidden(context); context.Writer.Status() != http.StatusForbidden {
		t.Error("we should have received a forbidden access")
	}
}

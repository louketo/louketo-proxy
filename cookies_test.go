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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDropCookie(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	dropCookie(context, "test-cookie", "test-value", 0, true)

	assert.Equal(t, context.Writer.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.1; Secure",
		"we have not set the cookie, headers: %v", context.Writer.Header())

	context = newFakeGinContext("GET", "/admin")
	dropCookie(context, "test-cookie", "test-value", 0, false)

	assert.Equal(t, context.Writer.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.1",
		"we have not set the cookie, headers: %v", context.Writer.Header())

	context = newFakeGinContext("GET", "/admin")
	dropCookie(context, "test-cookie", "test-value", 0, true)
	assert.NotEqual(t, context.Writer.Header().Get("Set-Cookie"),
		"test-cookie=test-value; Path=/; Domain=127.0.0.2; HttpOnly; Secure",
		"we have not set the cookie, headers: %v", context.Writer.Header())
}

func TestClearAccessTokenCookie(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	clearAccessTokenCookie(context, true)
	assert.Contains(t, context.Writer.Header().Get("Set-Cookie"),
		"kc-access=; Path=/; Domain=127.0.0.1; Expires=",
		"we have not cleared the, headers: %v", context.Writer.Header())
}

func TestClearRefreshAccessTokenCookie(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	clearRefreshTokenCookie(context, true)
	assert.Contains(t, context.Writer.Header().Get("Set-Cookie"),
		"kc-state=; Path=/; Domain=127.0.0.1; Expires=",
		"we have not cleared the, headers: %v", context.Writer.Header())
}

func TestClearAllCookies(t *testing.T) {
	context := newFakeGinContext("GET", "/admin")
	clearAllCookies(context, true)
	assert.Contains(t, context.Writer.Header().Get("Set-Cookie"),
		"kc-access=; Path=/; Domain=127.0.0.1; Expires=",
		"we have not cleared the, headers: %v", context.Writer.Header())
}

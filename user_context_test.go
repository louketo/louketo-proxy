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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsAudience(t *testing.T) {
	user := &userContext{
		audiences: []string{"test", "test2"},
	}
	if !user.isAudience("test") {
		t.Error("return should not have been false")
	}
	if user.isAudience("test1") {
		t.Error("return should not have been true")
	}
	if !user.isAudience("test2") {
		t.Error("return should not have been false")
	}
}

func TestGetUserRoles(t *testing.T) {
	user := &userContext{
		roles: []string{"1", "2", "3"},
	}
	if user.getRoles() != "1,2,3" {
		t.Error("we should have received a true resposne")
	}
	if user.getRoles() == "nothing" {
		t.Error("we should have received a false response")
	}
}

func TestIsExpired(t *testing.T) {
	user := &userContext{
		expiresAt: time.Now(),
	}
	if !user.isExpired() {
		t.Error("we should have been false")
	}
}

func TestIsBearerToken(t *testing.T) {
	user := &userContext{
		bearerToken: true,
	}
	assert.True(t, user.isBearer())
	assert.False(t, user.isCookie())
}

func TestIsCookie(t *testing.T) {
	user := &userContext{
		bearerToken: false,
	}
	assert.False(t, user.isBearer())
	assert.True(t, user.isCookie())
}

func TestGetUserContext(t *testing.T) {
	realmRoles := []string{"realm:realm"}
	clientRoles := []string{"client:client"}
	token := newTestToken("test")
	token.addRealmRoles(realmRoles)
	token.addClientRoles("client", []string{"client"})
	context, err := extractIdentity(token.getToken())
	assert.NoError(t, err)
	assert.NotNil(t, context)
	assert.Equal(t, "1e11e539-8256-4b3b-bda8-cc0d56cddb48", context.id)
	assert.Equal(t, "gambol99@gmail.com", context.email)
	assert.Equal(t, "rjayawardene", context.preferredName)
	assert.Equal(t, append(realmRoles, clientRoles...), context.roles)
}

func TestGetUserRealmRoleContext(t *testing.T) {
	roles := []string{"dsp-dev-vpn", "vpn-user", "dsp-prod-vpn", "openvpn:dev-vpn"}
	token := newTestToken("test")
	token.addRealmRoles(roles)
	context, err := extractIdentity(token.getToken())
	assert.NoError(t, err)
	assert.NotNil(t, context)
	assert.Equal(t, "1e11e539-8256-4b3b-bda8-cc0d56cddb48", context.id)
	assert.Equal(t, "gambol99@gmail.com", context.email)
	assert.Equal(t, "rjayawardene", context.preferredName)
	assert.Equal(t, roles, context.roles)
}

func TestUserContextString(t *testing.T) {
	token := newTestToken("test")
	context, err := extractIdentity(token.getToken())
	assert.NoError(t, err)
	assert.NotNil(t, context)
	assert.NotEmpty(t, context.String())
}

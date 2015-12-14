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

func TestGetUserContext(t *testing.T) {

}

func TestEncodeState(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)

	state := &SessionState{
		refreshToken: "this is a fake session",
		expireOn:     time.Now(),
	}

	session, err := proxy.encodeState(state)
	assert.NotEmpty(t, session)
	assert.NoError(t, err)
}

func TestDecodeState(t *testing.T) {
	proxy := newFakeKeycloakProxy(t)

	fakeToken := "this is a fake session"
	fakeExpiresOn := time.Now()

	state := &SessionState{
		refreshToken: fakeToken,
		expireOn:     fakeExpiresOn,
	}

	session, err := proxy.encodeState(state)
	assert.NotEmpty(t, session)
	if err != nil {
		t.Errorf("the encodeState() should not have handed an error")
		t.FailNow()
	}

	decoded, err := proxy.decodeState(session)
	assert.NotNil(t, decoded, "the session should not have been nil")
	if assert.NoError(t, err, "the decodeState() should not have thrown an error") {
		assert.Equal(t, fakeToken, decoded.refreshToken, "the token should been the same")
	}
}

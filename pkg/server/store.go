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

package server

import (
	"github.com/gambol99/keycloak-proxy/pkg/errors"
	"github.com/gambol99/keycloak-proxy/pkg/utils"

	"github.com/gambol99/go-oidc/jose"
	"go.uber.org/zap"
)

// useStore checks if we are using a store to hold the refresh tokens
func (r *oauthProxy) useStore() bool {
	return r.store != nil
}

// StoreRefreshToken the token to the store
func (r *oauthProxy) StoreRefreshToken(token jose.JWT, value string) error {
	return r.store.Set(utils.GetHashKey(&token), value)
}

// Get retrieves a token from the store, the key we are using here is the access token
func (r *oauthProxy) GetRefreshToken(token jose.JWT) (string, error) {
	// step: the key is the access token
	v, err := r.store.Get(utils.GetHashKey(&token))
	if err != nil {
		return v, err
	}
	if v == "" {
		return v, errors.ErrNoSessionStateFound
	}

	return v, nil
}

// DeleteRefreshToken removes a key from the store
func (r *oauthProxy) DeleteRefreshToken(token jose.JWT) error {
	if err := r.store.Delete(utils.GetHashKey(&token)); err != nil {
		r.log.Error("unable to delete token", zap.Error(err))

		return err
	}

	return nil
}

// Close is used to close off any resources
func (r *oauthProxy) CloseStore() error {
	if r.store != nil {
		return r.store.Close()
	}

	return nil
}

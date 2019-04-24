//+build nostores

package main

import (
	"errors"

	"github.com/coreos/go-oidc/jose"
)

func (r *Config) isStoreValid() error {
	if r.StoreURL != "" {
		return errors.New("remote stores are disabled in this build: you can't configure StoreURL")
	}
	return nil
}

func createStorage(location string) (storage, error) {
	return nil, nil
}

func (r *oauthProxy) useStore() bool {
	return false
}

func (r *oauthProxy) StoreRefreshToken(token jose.JWT, value string) error {
	return nil
}

func (r *oauthProxy) CloseStore() error {
	return nil
}

func (r *oauthProxy) GetRefreshToken(token jose.JWT) (string, error) {
	return "", nil
}

func (r *oauthProxy) DeleteRefreshToken(token jose.JWT) error {
	return nil
}

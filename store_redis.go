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
	"net/url"
	"time"

	log "github.com/Sirupsen/logrus"
	redis "gopkg.in/redis.v4"
)

type redisStore struct {
	client *redis.Client
}

// newRedisStore creates a new redis store
func newRedisStore(location *url.URL) (storage, error) {
	log.Infof("creating a redis client for store: %s", location.Host)

	// step: get any password
	password := ""
	if location.User != nil {
		password, _ = location.User.Password()
	}

	// step: parse the url notation
	client := redis.NewClient(&redis.Options{
		Addr:     location.Host,
		DB:       0,
		Password: password,
	})

	return redisStore{
		client: client,
	}, nil
}

// Set adds a token to the store
func (r redisStore) Set(key, value string) error {
	log.WithFields(log.Fields{
		"key":   key,
		"value": value,
	}).Debugf("adding the key: %s to the store", key)

	if err := r.client.Set(key, value, time.Duration(0)); err.Err() != nil {
		return err.Err()
	}

	return nil
}

// Get retrieves a token from the store
func (r redisStore) Get(key string) (string, error) {
	log.WithFields(log.Fields{
		"key": key,
	}).Debugf("retrieving the key: %s from store", key)

	result := r.client.Get(key)
	if result.Err() != nil {
		return "", result.Err()
	}

	return result.String(), nil
}

// Delete remove the key
func (r redisStore) Delete(key string) error {
	log.WithFields(log.Fields{
		"key": key,
	}).Debugf("deleting the key: %s from store", key)

	return r.client.Del(key).Err()
}

// Close closes of any open resources
func (r redisStore) Close() error {
	log.Infof("closing the resourcese for redis store")
	if r.client != nil {
		return r.client.Close()
	}

	return nil
}

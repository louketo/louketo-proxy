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
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/etcd-io/bbolt"
)

const (
	dbName = "louketo"
)

var (
	// ErrNoBoltdbBucket means the bucket does not exist
	ErrNoBoltdbBucket = errors.New("the boltdb bucket does not exists")
)

// A local file store used to hold the refresh tokens
type boltdbStore struct {
	client *bbolt.DB
}

func newBoltDBStore(location *url.URL) (storage, error) {
	// step: drop the initial slash
	path := strings.TrimPrefix(location.Path, "/")
	db, err := bbolt.Open(path, 0600, &bbolt.Options{
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	// step: create the bucket
	err = db.Update(func(tx *bbolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(dbName))
		return e
	})

	return &boltdbStore{
		client: db,
	}, err
}

// Set adds a token to the store
func (r *boltdbStore) Set(key, value string, expiration time.Duration) error {
	return r.client.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(dbName))
		if bucket == nil {
			return ErrNoBoltdbBucket
		}
		return bucket.Put([]byte(key), []byte(value))
	})
}

// Get retrieves a token from the store
func (r *boltdbStore) Get(key string) (string, error) {
	var value string
	err := r.client.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(dbName))
		if bucket == nil {
			return ErrNoBoltdbBucket
		}
		value = string(bucket.Get([]byte(key)))
		return nil
	})

	return value, err
}

// Delete removes the key from the bucket
func (r *boltdbStore) Delete(key string) error {
	return r.client.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(dbName))
		if bucket == nil {
			return ErrNoBoltdbBucket
		}
		return bucket.Delete([]byte(key))
	})
}

// Close closes of any open resources
func (r *boltdbStore) Close() error {
	return r.client.Close()
}

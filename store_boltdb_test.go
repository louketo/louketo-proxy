/*
Copyright 2017 All rights reserved.

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
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeBoltDBStore struct {
	storedb *os.File
	store   *boltdbStore
}

func (f *fakeBoltDBStore) close() {
	if f.storedb != nil {
		f.storedb.Close()
		os.Remove(f.storedb.Name())
	}
}

func newTestBoldDB(t *testing.T) *fakeBoltDBStore {
	tmpfile, err := ioutil.TempFile("/tmp", "louketo-proxy")
	if err != nil {
		t.Fatalf("unable to create temporary file, error: %s", err)
	}
	u, err := url.Parse(fmt.Sprintf("file:///%s", tmpfile.Name()))
	if err != nil {
		t.Fatalf("unable to parse file url, error: %s", err)
	}
	s, err := newBoltDBStore(u)
	if err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		t.Fatalf("unable to test boltdb, error: %s", err)
	}
	return &fakeBoltDBStore{tmpfile, s.(*boltdbStore)}
}

func TestNewBoltDBStore(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()
	assert.NotNil(t, s)
}

func TestBoltSet(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()
	err := s.store.Set("test", "value", 0)
	assert.NoError(t, err)
}

func TestBoltGet(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()

	v, err := s.store.Get("test")
	assert.NoError(t, err)
	assert.Empty(t, v)

	err = s.store.Set("test", "value", 0)
	assert.NoError(t, err)

	v, err = s.store.Get("test")
	assert.NoError(t, err)
	assert.Equal(t, "value", v)
}

func TestBoltDelete(t *testing.T) {
	keyname := "test"
	value := "value"
	s := newTestBoldDB(t)
	defer s.close()
	err := s.store.Set(keyname, value, 0)
	assert.NoError(t, err)
	v, err := s.store.Get(keyname)
	assert.NoError(t, err)
	assert.Equal(t, value, v)
	err = s.store.Delete(keyname)
	assert.NoError(t, err)
	v, err = s.store.Get(keyname)
	assert.NoError(t, err)
	assert.Empty(t, v)
}

func TestBoldClose(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()
	err := s.store.Close()
	assert.NoError(t, err)
}

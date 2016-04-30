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
	"fmt"
	"net/url"
)

// newStorage creates the store client for use
func newStorage(location string) (storage, error) {
	var store storage
	var err error

	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "redis":
		store, err = newRedisStore(u)
	case "boltdb":
		store, err = newBoltDBStore(u)
	default:
		return nil, fmt.Errorf("unsupport store: %s", u.Scheme)
	}

	return store, err
}

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
)

func TestIsAudience(t *testing.T) {
	user := &userContext{
		audience: "test",
	}
	if !user.isAudience("test") {
		t.Errorf("return should not have been false")
	}
	if user.isAudience("test1") {
		t.Errorf("return should not have been true")
	}
}

func TestGetROles(t *testing.T) {
	user := &userContext{
		roles: []string{"1", "2", "3"},
	}
	if user.getRoles() != "1,2,3" {
		t.Errorf("we should have received a true resposne")
	}
	if user.getRoles() == "nothing" {
		t.Errorf("we should have recieved a false response")
	}
}

func TestIsExpired(t *testing.T) {
	user := &userContext{
		expiresAt: time.Now(),
	}
	if !user.isExpired() {
		t.Errorf("we should have been false")
	}
}

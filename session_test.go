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
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetSessionToken(t *testing.T) {
	token := getFakeAccessToken(t)
	encoded := token.Encode()

	testCases := []struct {
		Context *gin.Context
		Ok      bool
	}{
		{
			Context: &gin.Context{
				Request: &http.Request{
					Header: http.Header{
						"Authorization": []string{fmt.Sprintf("Bearer %s", encoded)},
					},
				},
			},
			Ok: true,
		},
		{
			Context: &gin.Context{
				Request: &http.Request{
					Header: http.Header{},
				},
			},
		},
		// @TODO need to other checks
	}

	for i, c := range testCases {
		user, err := getIdentity(c.Context)
		if err != nil && c.Ok {
			t.Errorf("test case %d should not have errored", i)
			continue
		}
		if err != nil && !c.Ok {
			continue
		}
		if user.token.Encode() != encoded {
			t.Errorf("test case %d the tokens are not the same", i)
		}
	}
}

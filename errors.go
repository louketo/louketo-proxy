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

import "net/http"

var (
	accessForbiddenError = &apiError{
		Message: "access forbidden to resource",
		Code:    http.StatusForbidden,
	}
	sessionNotFoundError = &apiError{
		Message: "session not found",
		Code:    http.StatusForbidden,
	}
)

// apiError is a generic error type for handler responses
type apiError struct {
	Message string
	Code    int
}

func (a *apiError) Error() string {
	return a.Message
}

func newAPIError(message string, code int) error {
	return &apiError{
		Message: message,
		Code:    code,
	}
}

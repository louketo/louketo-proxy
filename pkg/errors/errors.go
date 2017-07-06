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

package errors

import "errors"

var (
	// ErrSessionNotFound no session found in the request
	ErrSessionNotFound = errors.New("authentication session not found")
	// ErrNoSessionStateFound means there was not persist state
	ErrNoSessionStateFound = errors.New("no session state found")
	// ErrInvalidSession the session is invalid
	ErrInvalidSession = errors.New("invalid session identifier")
	// ErrAccessTokenExpired indicates the access token has expired
	ErrAccessTokenExpired = errors.New("the access token has expired")
	// ErrRefreshTokenExpired indicates the refresh token as expired
	ErrRefreshTokenExpired = errors.New("the refresh token has expired")
	// ErrNoTokenAudience indicates their is not audience in the token
	ErrNoTokenAudience = errors.New("the token does not audience in claims")
	// ErrDecryption indicates we can't decrypt the token
	ErrDecryption = errors.New("failed to decrypt token")
	// ErrUnsupportedStore indicates the storage type is not supported
	ErrUnsupportedStore = errors.New("unsupport store type")
	// ErrDecryptionTextSmall indicates the encryption key is too small
	ErrDecryptionTextSmall = errors.New("failed to decrypt the ciphertext, the text is too short")
	// ErrUserInfoValidation indicates the token was not validated by userinfo endpoint
	ErrUserInfoValidation = errors.New("token not validate by userinfo endpoint")
)

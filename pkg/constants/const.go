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

package constants

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

var (
	// Release is the release version
	Release = "v2.1.0-rc2"
	// Gitsha is the gitsha
	Gitsha = "no gitsha provided"
	// Compiled is the build time
	Compiled = "0"
	// Version is a version string
	Version = ""
)

const (
	// Prog is the name of the service
	Prog = "keycloak-proxy"
	// Author is the writer
	Author = "Rohith Jayawardene"
	// Email is the author email
	Email = "gambol99@gmail.com"
	// Description is a short hand description
	Description = "is a proxy using the keycloak service for auth and authorization"
	// ClaimPreferredName is the keycloak username claim
	ClaimPreferredName = "preferred_username"
	// ClaimAudience is tha audience claim
	ClaimAudience = "aud"
	// ClaimResourceAccess is the keycloak client roles
	ClaimResourceAccess = "resource_access"
	// ClaimRealmAccess is the keycloak realm roles
	ClaimRealmAccess = "realm_access"
	// ClaimResourceRoles is the roles claims
	ClaimResourceRoles = "roles"
	// HeaderUpgrade indicates a connecttion upgrade1
	HeaderUpgrade = "Upgrade"
	// HTTPSchema is the http schema
	HTTPSchema = "http"
	// HTTPSSchema is the https schema
	HTTPSSchema = "https"
	// HeaderXForwardedFor is a HTTP header
	HeaderXForwardedFor = "X-Forwarded-For"
	// HeaderXForwardedProto is a HTTP header
	HeaderXForwardedProto = "X-Forwarded-Proto"
	// HeaderXForwardedProtocol is a HTTP header
	HeaderXForwardedProtocol = "X-Forwarded-Protocol"
	// HeaderXForwardedSSL is a HTTP header
	HeaderXForwardedSSL = "X-Forwarded-SSL"
	// HeaderXRealIP is a HTTP header
	HeaderXRealIP = "X-Real-IP"
	// AuthorizationHeader is a http authorization header
	AuthorizationHeader = "Authorization"
	// VersionHeader is a verion http header
	VersionHeader = "X-Auth-Proxy-Version"

	// OauthURL is the base oauth uri
	OauthURL = "/oauth"
	// AuthorizationURL is the uri for oauth authorization
	AuthorizationURL = "/authorize"
	// CallbackURL is the uri for oauth callbacks
	CallbackURL = "/callback"
	// ExpiredURL is the expiration handler
	ExpiredURL = "/expired"
	// HealthURL is the health handler
	HealthURL = "/health"
	// LoginURL is the login handler
	LoginURL = "/login"
	// LogoutURL is the logout handler
	LogoutURL = "/logout"
	// MetricsURL is the uri for the metrics handler
	MetricsURL = "/metrics"
	// TokenURL is the uri for the tokens handler
	TokenURL = "/token"
	// DebugURL is the uri for the debug endpoint
	DebugURL = "/debug/pprof"
)

var (
	// AllHTTPMethods contains all the http methods
	AllHTTPMethods = []string{
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	}
)

// GetVersion returns the proxy version
func GetVersion() string {
	if Version == "" {
		tm, err := strconv.ParseInt(Compiled, 10, 64)
		if err != nil {
			return "unable to parse compiled time"
		}
		Version = fmt.Sprintf("%s (git+sha: %s, built: %s)", Release, Gitsha, time.Unix(tm, 0).Format("02-01-2006"))
	}

	return Version
}

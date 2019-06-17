/*
Package version holds build information defined at build time for gatekeeper
*/
package version

import (
	"fmt"
	"strconv"
	"time"
)

const (
	// Prog is this program name
	Prog = "keycloak-gatekeeper"
	// Author of this package
	Author = "oneconcern"
	// Email address for inquiries
	Email = "frederic@oneconcern.com"
	// Description of gatekeeper
	Description = "is a transparent authenticating proxy using the keycloak service for authentication and authorization"
)

var (
	// Release tag
	Release = "unreleased - dev"
	// Gitsha is the git hash
	Gitsha = "no gitsha provided"
	// Compiled is the build timestamp
	Compiled = "0"
	// Version overrides default settings with some arbitrary string, if defined
	Version = ""
)

// GetVersion returns the proxy version
func GetVersion() string {
	if Version == "" {
		tm, err := strconv.ParseInt(Compiled, 10, 64)
		if err != nil {
			return "unable to parse build time"
		}
		Version = fmt.Sprintf("%s (git+sha: %s, built: %s)", Release, Gitsha, time.Unix(tm, 0).Format(time.RFC1123))
	}

	return Version
}

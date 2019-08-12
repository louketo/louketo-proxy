[![GoDoc](http://godoc.org/github.com/oneconcern/keycloak-gatekeeper?status.png)](http://godoc.org/github.com/oneconcern/keycloak-gatekeeper)
[![GitHub version](https://badge.fury.io/gh/oneconcern%2Fkeycloak-gatekeeper.svg)](https://badge.fury.io/gh/oneconcern%2Fkeycloak-gatekeeper)
[![Go Report Card](https://goreportcard.com/badge/github.com/oneconcern/keycloak-gatekeeper)](https://goreportcard.com/report/github.com/oneconcern/keycloak-gatekeeper)
[![CircleCI](https://circleci.com/gh/oneconcern/keycloak-gatekeeper.svg?style=svg)](https://circleci.com/gh/oneconcern/keycloak-gatekeeper)


Oneconcern's Keycloak Gatekeeper
----------------------------------

This is a fork of [keycloak-gatekeeper](https://github.com/keycloak/keycloak-gatekeeper), maintained by Oneconcern Inc.

We try our best to contribute back fixes, enhancements and new features to the main repo.

### What does it do?

Keycloak Gatekeeper is a transparent authentication proxy that integrates with the [Keycloak](https://github.com/keycloak/keycloak) authentication service.

Gatekeeper may run as a reverse proxy or as a forwarding proxy.

Our primary use case is reverse proxy: this means that you may setup a defense-in-depth and protect API resources behind this proxy, 
with users authenticated against Keycloak.

Our primary target is browser apps (e.g. react) directly using this proxy to access API resources.

> **Disclaimer**: although we try not to regress on what we see as non-goals, we don't provide any further testing than the one already in place
> on forward proxying, backend session-stores and login UI with templates.

Authentication is stateful: gatekeeper creates a session for authenticated users. This session may be either stored in some backend or in
(encrypted) cookies.

### Authentication modes

The service supports both access tokens in browser cookie or bearer tokens.

This means that traditional clients using a bear token in `Authorization` header may pass through the proxy, as well as modern browser-based clients
which acquire a token through the proxy authentication service, then use a cookie to authenticate.

Protected resources may be unauthenticated, authenticated with custom headers deduced from the token claims or carry out full authentication again from
the `Authorization` header (defense in depth).

> NOTE: gatekeeper expects to be listed in the audience claim of ID tokens brought back by keycloak.
> So you should ensure your gatekeeper client in keycloak is configured with a proper "audience" token mapper.

### Authorization

Protected resources (URIs) may be guarded with some basic RBAC rules checking groups and roles provided by keycloak.

> NOTE: group rules support trailing wildcards, so you may configure group claims to be the full group hierarchical path.
> This requires your token mapper in keycloak to map groups in claim with path rather than group name.

### Features

* Proxied access token exchange flow (`/oauth/authorize` endpoint)
* CORS support
* HTTP/2 support (caution: HTTP/2 push not supported yet)
* Authentication support with cookie or token in header
* Hybrid authentication modes allowed, e.g. token in header vs cookies
* Cookies compression
* Large cookies are split in chunks
* Opt-in: when authenticating with cookies, an automatic CSRF mechanism may be used for additional protection
* Access tokens managed by cookies are refreshed automatically
* Mutual TLS & TLS fine-tuning settings (cipher suites, etc.)
* Routing to multiple upstreams (e.g. with base path)
* Client may force instant token refresh (`/oauth/refresh` endpoint)
* Client logout (`/oauth/logout` endpoint)
* Client access to token claims (`/oauth/token` endpoint)
* Client may check the expiry status of its access token (`/oauth/expired` endpoint)

### Topology

The reverse proxy may be deployed either as a gateway or as a sidecar.

When used as gateway, you may route to different upstreams, with some basic path prefix stripping rules.

When relying on cookies, and when used as sidecar or when set with multiple instances on different upstreams,
you must ensure that cookies domain and cookies encryption key are shared by all instances.

Multiple gatekeepers may be set up: if you are using cookies to authenticate, you must:
1. Deploy multiple instances with the same encryption secret
2. Define a common domain for cookies to be shared

### Operations
All the below endpoints may be optionally exposed on a separate port, or restricted to localhost requests.

#### Metrics

Gatekeeper exposes prometheus metrics and health status endpoint. Metrics are enabled by default.
```
enable-metrics: true
```

```
/oauth/metrics
```

#### Health status

```
/oauth/health
```

#### Profiling
There is an opt-in live profiler endpoint for debugging performance issues:
```
enable-profiling: true
```

```
/debug/pprof/{name}
```

This serves commands from the pprof handler described [here](https://golang.org/pkg/net/http/pprof/#pkg-index).

#### Tracing

Opencensus tracing may be enabled with the `enable-tracing: true` parameter. When enabled a trace collecting agent _must_ be configured (e.g. Jaeger agent).

The admin listener (or main listener if not enabled) exposes zpages (rpcz, tracez):

```
/oauth/trace/rpcz
/oauth/trace/tracez
```

TODOS
----------------------------------

There is still quite some room for improvement:

* [x] opencensus tracing
* [ ] cookie compression (allow this as an option)
* [ ] virtual hosts w/ routing rules
* [ ] http2 support w/ push
* [ ] csrf cookie w/ session store (at the moment, csrf state is only supported as a client-side cookie)
* [ ] refactor session store to move to internal packages
* [ ] upgrade from coreos/oidc V1
* [ ] support ECDSA-signed tokens
* [ ] support keycloak client admin URL features (nbf policy push, logout push)
* [ ] support leeway to avoid shared-state race conditions on refreshing acess tokens with revokable refresh tokens

Reporting security vulnerabilities
----------------------------------

If you've found a security vulnerability, please report back to [us](mailto:frederic@oneconcern.com)


Help and Documentation
----------------------

This fork:

* [Issues](https://github.com/oneconcern/keycloak-gatekeeper/issues) - Issue tracker for bugs and feature requests

Resources associated to the original repo:

* [JIRA](https://issues.jboss.org/projects/KEYCLOAK) - Issue tracker for bugs and feature requests
* [Documentation](https://www.keycloak.org/docs/latest/securing_apps/index.html#_keycloak_generic_adapter) - User Guide
* [User Mailing List](https://lists.jboss.org/mailman/listinfo/keycloak-user) - Mailing list to ask for help and general questions about Keycloak
* [Developer Mailing List](https://lists.jboss.org/mailman/listinfo/keycloak-dev) - Mailing list to discuss development of Keycloak

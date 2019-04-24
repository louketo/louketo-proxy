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

> **Disclaimer**: although we try not to regress on what we see as non-goals, we don't provide any further testing than the one already in place, 
> on forward proxying, backend session-stores and login UI with templates.

Authentication is stateful: gatekeeper creates a session for authenticated users. This session may be either stored in some backend or in an
(encrypted) cookie.

### Authentication modes

The service supports both access tokens in browser cookie or bearer tokens.

This means that traditional clients using a bear token in `Authorization` header may pass through the proxy, as well as modern browser-based clients
which acquire a token through the proxy authentication service, then use a cookie to authenticate.

Protected resources may be unauthenticated, authenticated with custom headers deduced from the token claims or carry out full authentication again from
the `Authorization` header (defense in depth).

> NOTE: gatekeeper expects to be listed in the audience claim of ID tokens brought back by keycloak

### Authorization

Protected resources (URIs) may be guarded with some basic RBAC rules checking groups and roles provided by keycloak.

> NOTE: group rules support trailing wildcards, so you may configure group claims to be the full group hierarchical path.


### Features

* Proxied access token exchange flow
* CORS support
* Authentication support with cookie or token in header
* Large cookies are split in chunks
* When authenticating with cookies, an automatic CSRF mechanism may be used for additional protection
* Access tokens managed by cookies are refreshed automatically


### Topology

The reverse proxy may be deployed either as a gateway or as a sidecar.

When used as gateway, you may route to different upstreams, with some basic path prefix stripping rules.

When used as sidecar, or when set with multiple instances on different upstreams, you must ensure that cookies domain and cookies encryption key
are shared by all instances.


### Operations

Gatekeeper exposes prometheus metrics and health status endpoint.

These may be optionally exposed on a separate port, or restricted to localhost requests.


Reporting security vulnerabilities
----------------------------------

If you've found a security vulnerability, please report back to [us](mailto:frederic@oneconcern.com)


Help and Documentation
----------------------

This fork:

* [Issues](https://github.com/oneconcern/keycloak-gatekeeper/issues) - Issue tracker for bugs and feature requests

Resources with original repo:

* [JIRA](https://issues.jboss.org/projects/KEYCLOAK) - Issue tracker for bugs and feature requests
* [Documentation](https://www.keycloak.org/docs/latest/securing_apps/index.html#_keycloak_generic_adapter) - User Guide
* [User Mailing List](https://lists.jboss.org/mailman/listinfo/keycloak-user) - Mailing list to ask for help and general questions about Keycloak
* [Developer Mailing List](https://lists.jboss.org/mailman/listinfo/keycloak-dev) - Mailing list to discuss development of Keycloak

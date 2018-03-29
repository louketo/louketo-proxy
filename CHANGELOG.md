
#### **2.1.2 (Unreleased)**

FEATURES:
* Added a --enable-default-deny option to make denial by default [#PR320](https://github.com/gambol99/keycloak-proxy/pull/320)
* Added a `enable-logout-redirect` which redirects the /oauth/logout to the provider [#PR327](https://github.com/gambol99/keycloak-proxy/pull/327)
* Added environment variables alternatives for the forwarding username and password [#PR329]https://github.com/gambol99/keycloak-proxy/pull/329)
* Added metrics latency metrics for the forwarding proxy and the certificate rotation [#PR325](https://github.com/gambol99/keycloak-proxy/pull/325)
* Added spelling check to the tests [#PR322](https://github.com/gambol99/keycloak-proxy/pull/322)
* Added the X-Auth-Audience to the upstream headers [#PR319](https://github.com/gambol99/keycloak-proxy/pull/319)
* Added the ability to control the timeout on the initial openid configuration from .well-known/openid-configuration [#PR315](https://github.com/gambol99/keycloak-proxy/pull/315)
* Added the feature to customize the oauth prefix (defaults to /oauth) [#PR326](https://github.com/gambol99/keycloak-proxy/pull/326)
* Adding additional metrics covering provider request latency, token breakdown [#PR324](https://github.com/gambol99/keycloak-proxy/pull/324)
* Changed the upstream-keepalive to default to true [#PR321](https://github.com/gambol99/keycloak-proxy/pull/321)
* Force configuration to use the wildcard [#PR338](https://github.com/gambol99/keycloak-proxy/pull/338)
* Updated the docker base image alpine 3.7 [#PR313](https://github.com/gambol99/keycloak-proxy/pull/313)
* Updated to Golang version 1.10 [#PR316](https://github.com/gambol99/keycloak-proxy/pull/316)

FIXES:
* Fixed a redirection bug [#PR337](https://github.com/gambol99/keycloak-proxy/pull/337)

#### **2.1.1**

FEATURES:
* Added the groups parameter to the resource, permitting users to use the `groups` claim in the token [#PR301](https://github.com/gambol99/keycloak-proxy/pull/301)
* Removed the authors file [#PR299](https://github.com/gambol99/keycloak-proxy/pull/299)

FIXES:
* Fixed the custom headers when upgrading to websockets [#PR311](https://github.com/gambol99/keycloak-proxy/pull/311)
* Fixed exception when upgrading to websockets [#PR303](https://github.com/gambol99/keycloak-proxy/pull/303)

#### **2.1.0**

FIXES:
* fixed the parsing of slices for command line arguments (i.e. --cors-origins etc)
* fixed any accidental proxying on the /oauth or /debug URI
* removed all references to the underlining web framework in tests
* adding unit tests for proxy protocol and using the run() method [#PR214](https://github.com/gambol99/keycloak-proxy/pull/214)
* removed unnecessary commands in the Dockerfile [#PR213](https://github.com/gambol99/keycloak-proxy/pull/213)
* removed the unrequired testing tools [#PR210](https://github.com/gambol99/keycloak-proxy/pull/210)
* fixed a number of linting errors highlighted by gometalinter [#PR209](https://github.com/gambol99/keycloak-proxy/pull/209)
* added docker image instructions to the readme [#PR204](https://github.com/gambol99/keycloak-proxy/pull/204)
* added unit tests for the debug handlers [#PR223](https://github.com/gambol99/keycloak-proxy/pull/223)
* fixing the logout handler panic when revocation url is not set [#PR254](https://github.com/gambol99/keycloak-proxy/pull/254)
* fixing the Host header on the forwarding proxy [#PR290](https://github.com/gambol99/keycloak-proxy/pull/290)

FEATURES
* changed the routing engine from gin to echo
* we now normalize all inbound URI before applying the protection middleware
* the order of the resources are no longer important, the framework will handle the routing [#PR199](https://github.com/gambol99/keycloak-proxy/pull/199)
* improved the overall spec of the proxy by removing URL inspection and prefix checking [#PR199](https://github.com/gambol99/keycloak-proxy/pull/199)
* removed the CORS implementation and using the default echo middles, which is more compliant [#PR199](https://github.com/gambol99/keycloak-proxy/pull/199)
* added a warning for suspect resource urls not using wildcards [#PR206](https://github.com/gambol99/keycloak-proxy/pull/206)
* added a build time to the version tag [#PR212](https://github.com/gambol99/keycloak-proxy/pull/212)
* added coveralls coverage submission to the ci build [#PR215](https://github.com/gambol99/keycloak-proxy/pull/215)
* added spelling code coverage to the ci build [#PR208](https://github.com/gambol99/keycloak-proxy/pull/208)
* update the encryption to use aes gcm [#PR220](https://github.com/gambol99/keycloak-proxy/pull/220)
* added the --enable-encrypted-token option to enable encrypting the access token:wq
* added the --skip-client-id option to permit skipping the verification of the auduence against client in token [#PR236](https://github.com/gambol99/keycloak-proxy/pull/236)
* updated the base image to apline 3.6 in commit [0fdebaf821](https://github.com/gambol99/keycloak-proxy/pull/236/commits/0fdebaf8215e9480896f01ec7ab2ef7caa242da1)
* moved to use zap for the logging [#PR237](https://github.com/gambol99/keycloak-proxy/pull/237)
* making the X-Auth-Token optional in the upstream headers via the --enable-token-header [#PR247](https://github.com/gambol99/keycloak-proxy/pull/247)
* adding the ability to load a CA authority to provide trust on upstream endpoint [#PR248](https://github.com/gambol99/keycloak-proxy/pull/248)
* adding the ability to set various http server and upstream timeout [#PR268](https://github.com/gambol99/keycloak-proxy/pull/268)
* adding the `--enable-authorization-cookies` command line option to control upstream cookies [$PR287](https://github.com/gambol99/keycloak-proxy/pull/287)

BREAKING CHANGES:
* the proxy no longer uses prefixes for resources, if you wish to use wildcard urls you need
  to specify it, i.e. --resource=/ becomes --resource=/* or =admin/ becomes =admin/* or /admin*;
  a full set of routing details can bt found at https://echo.labstack.com/guide/routing [#PR199](https://github.com/gambol99/keycloak-proxy/pull/199)
* removed the --enable-cors-global option, CORS is now handled the default echo middleware
* changed option from log-requests -> enable-logging [#PR199](https://github.com/gambol99/keycloak-proxy/pull/199)
* changed option from json-format -> enable-json-logging [#PR199](https://github.com/gambol99/keycloak-proxy/pull/199)

MISC:
* Switch to using a go-oidc [fork](https://github.com/gambol99/go-oidc/commit/2111f98a1397a35f1800f4c3c354a7abebbef75c) for now, until i get the various bit merged upstream

#### **2.0.7**

FIXES:
 * Backported Fix to the proxy proxy call [767967c3](https://github.com/gambol99/keycloak-proxy/commit/767967c3499795e3141e74cace5ae3d70f27cf61)

#### **2.0.6**

FIXES:
 * Ensuring we abort all requests to /oauth/ [#PR205](https://github.com/gambol99/keycloak-proxy/pull/205)

#### **2.0.5**

FIXES:
 * We normalize all urls before the protection middleware is applied [#PR202](https://github.com/gambol99/keycloak-proxy/pull/202)

#### **2.0.4**

FIXES:
 * Fixes a bug in authentication, which permitted double slashed url entry [#PR200](https://github.com/gambol99/keycloak-proxy/pull/200)

FEATURES:
 * Grabbing the revocation-url from the idp config if user override is not specified [#PR193](https://github.com/gambol99/keycloak-proxy/pull/193)

#### **2.0.3**

FEATURES:
 * Adding the PROXY_ENCRYPTION_KEY environment varable [#PR191](https://github.com/gambol99/keycloak-proxy/pull/191)

#### **2.0.2**

FEATURES:
 * Adding the --enable-cors-global to switch on CORs header injects into every response [#PR174](https://github.com/gambol99/keycloak-proxy/pull/174)
 * Adding the ability to reload the certificates when the change [#PR178](https://github.com/gambol99/keycloak-proxy/pull/178)
 * Removing the requirement of a redirection-url, if none is specified it will use Host header or the X-Forwarded-Host if present [#PR183](https://github.com/gambol99/keycloak-proxy/pull/183)

CHANGES:
 * Updated the gin dependency to latest version and removed dependency in tests for gin [#PR181](https://github.com/gambol99/keycloak-proxy/pull/181)
 * Updated to go-proxy to the latest version [#PR180](https://github.com/gambol99/keycloak-proxy/pull/180)
 * Fixed up some spelling mistakes [#PR177](https://github.com/gambol99/keycloak-proxy/pull/177)
 * Changed the CLI to use reflection of the config struct [#PR176](https://github.com/gambol99/keycloak-proxy/pull/176)
 * Updated the docker base image to alpine:3.5 [#PR184](https://github.com/gambol99/keycloak-proxy/pull/184)
 * Added a new options to control the access token duration [#PR188](https://github.com/gambol99/keycloak-proxy/pull/188)

BUGS:
 * Fixed the time.Duration flags in the reflection code [#PR173](https://github.com/gambol99/keycloak-proxy/pull/173)
 * Fixed the environment variable type [#PR176](https://github.com/gambol99/keycloak-proxy/pull/176)
 * Fixed the refresh tokens, the access token cookie was timing out too quickly ([#PR188](https://github.com/gambol99/keycloak-proxy/pull/188)

#### **2.0.1**

BUGS:
 * fixing the cli option for --resources. Need to start writing tests for the cli options

#### **2.0.0**

FEATURES:
 * Adding the --skip-openid-provider-tls-verify option to bypass the TLS verification for Idp [#PR147](https://github.com/gambol99/keycloak-proxy/pull/147)
 * Added a http service to permit http -> https redirects --enable-https-redirect [#PR126](https://github.com/gambol99/keycloak-proxy/pull/162)
 * Added a pprof debug handler to support profiling the proxy, via --enable-profiling [#PR156](https://github.com/gambol99/keycloak-proxy/pull/156)

FIXES:
 * Fixed the --headers and --tags command line options, had a typo on the mergeMaps method [#PR142](https://github.com/gambol99/keycloak-proxy/pull/142)
 * Cleaned up how the cli command line options are processed [#PR164](https://github.com/gambol99/keycloak-proxy/pull/164)
 * Cleaned up the option checking for forwarding proxy tls setting [#PR163](https://github.com/gambol99/keycloak-proxy/pull/163)
 * Using timeout rather than multiple attempts for discovery url [#PR153](https://github.com/gambol99/keycloak-proxy/pull/153)
 * Updated the go-oidc library with various fixes [#PR159](https://github.com/gambol99/keycloak-proxy/pull/159)

BREAKING CHANGES:
 * The login handler by default has been switched off, you must enable for --enable-login-handler [#PR]()
 * Changed the CORS format in the configuration file
 * Changed the command line options scope -> scopes
 * Changed the command line options log-json-format -> json-format
 * Changed the command line options resource -> resources
 * Changed the command line options tags -> tags

#### **1.2.8**

FIXES:
 * Fixed a bug in the --cookie-domain options
 * Added unit test for the cookie-domain options
 * Switched to using set rather than add to the headers

#### **1.2.7**

FIXES:
 * Added unit tests for the logout handlers
 * Added unit tests for the authorization header handling

FEATURES:
 * Allow the user to enable or disable adding the Authorization header

#### **1.2.6**

FIXES:
 * Fixes the revocation url bug

FEATURES:
 * Adds the ability to control the http-only cookie option, default to false

#### **1.2.5**

FIXES:
 * Fixes the /oauth/login handler to return 401 on failed logins

#### **1.2.4**

FEATURES
 * Added the ability to set the forwarding proxy certificates
 * Added logging for outbound forward signing requests

FIXES:
 * Fixes the expiration of the access token, if no idle-duration is
 * Fixed the forwarding proxy for SSL
 * Fixed the bug in the containedSubString method

BREAKING CHANGES:
 * Fixed up the config resource definition to use 'uri' not 'url'
 * Removed the --idle-duration option, was never really implemented well

#### **1.2.3**

FEATURES:
 * Added a prometheus metrics endpoint, at present a break down by status_code is provided
 * Added the ability to override the cookie domain from the default host header
 * Added the ability to load a client certificate used by the reverse and forwarding upstream proxies.

TODO:
 * Need a means to updating the client certificate once expired.

CHANGES:
 * Updated the godeps for codegangsta cli to it's renamed version

FIXES:
 * Fixed the environment variable command line options, the IsSet in cli does not check environment
   variable setters

#### **1.2.2**

CHANGES:
 * General Code fix uo
 * removing from dockerfile user and group

#### **1.2.1**

CHANGES:
 * Updated the dockerfile to create a user and group and not run at root

#### **1.2.0**

BREAKING CHANGES:
 * Changed the /oauth/login handler to use post form values rather than query parameter to ensure (to a degree) they
   are not logged

#### **1.1.1**

FIXES:
 * Fixed the configuration bug which required a redirection-url even when redirection was shifted off

#### **1.1.0**

FIXES:
 * Added a auto build to quay.io on the travis build for master and tags
 * Fixed the host header to proxy to upstreams outside of the proxy domain (https://github.com/golang/go/issues/7618)
 * Adding a git+sha to the usage
 * Defaulting to gin mode release unless verbose is true
 * Removed the gin debug logging for tests and builds
 * Removed the default upstream, as it caught people by surprise and some accidentally forwarded to themselves
 * Changed the state parameter (which is used as a redirect) to base64 the value allowing you to use complex urls

FEATURES:
 * Adding environment variables to some of the command line options
 * Adding the option of a forwarding agent, i.e. you can seat the proxy front of your application,
   login to keycloak and use the proxy as forwarding agent to sign outbound requests.
 * Adding the version information into a header on /oauth/health endpoint
 * Removed the need to specify a client-secret, which means to cope with authz only or public endpoints
 * Added role url tokenizer, /auth/%role%/ will extract the role element and check the token as it
 * Added proxy protocol support for the listening socket (--enable-proxy-protocol=true)
 * Added the ability to listen on a unix socket

BREAKING CHANGES:
 * Changed the X-Auth-Subject, it not is the actual subject from the token (makes more sense).
   X-Auth-UserID will either be the subject id or the preferred username

#### **1.0.6 (May 6th, 2016)**

FIXES:
 * Fixed the logout endpoint, ensuring users sessions are revoked. Note: i've not really tested this against Keycloak
   and Google. Revocation or logouts seems to have somewhat scattered implementation across providers.

#### **1.0.5 (May 3th, 2016)**

FEATURES:
 * You can choose the cookie name of the access and refresh token via --cookie-{access,refresh}-name
 * An additional option --add-claims to inject custom claims from the token into the authentication headers
   i.e. --add-claims=given_name would add X-Auth-Given-Name (assumed the claims exists)
 * Added the --secure-cookie option to control the 'secure' flag on the cookie

BREAKING CHANGES:
 * Changed the claims option from 'claims' to 'match-claims' (command line and config)
 * Changed keepalive config option to the same as the command line 'keepalive' -> 'upstream-keepalives'
 * Changed the config option from 'upstream' to 'upstream-url', same as command line

#### **1.0.4 (April 30th, 2016)**

FIXES:
 * Fixes the cookie sessions expiration

FEATURES:
 * Adding a idle duration configuration option which controls the expiration of access token cookie and thus session.
   If the session is not used within that period, the session is removed.
 * The upstream endpoint has also be a unix socket

BREAKING CHANGES:
 * Change the client id in json/yaml config file from clientid -> client-id

#### **1.0.2 (April 22th, 2016)**

FIXES:
 * Cleaned up a lot of code base to make this simpler
 * Fixed elements in the refresh tokens and simplified the controller
 * Removed of the code out from methods into functions to reduce the dependencies (unit testing is easier as well)
 * Fixed how the refresh tokens are implemented, i was somewhat confused between refresh token and offline token
 * Fixed the encryption key length, must be either 16 or 32 for aes-128/256 selection

FEATURES:
 * Added the ability to store the refresh token in either local boltdb file or a redis service rather than
   an encrypted cookie (note, the token regardless is encrypted)
 * Added a /oauth/logout endpoint to logout the user
 * Added a /oauth/login (niche requirement) to provide grant_type=password requests

TODO:
 * Really need to mock a oauth server to simplify the unit tests

BREAKING CHANGES:
 * Changed the following configuration options to conform to their command line equivalents
   - refresh_sessions -> refresh-sessions
   - discovery_url      -> discovery-url
   - redirection_url    -> redirection-url
   - tls_ca_certificate -> tls-ca-certificate
   - tls_private_key    -> tls-private-key
   - tls_cert           -> tls-cert
   - log_json_format    -> log-json-format
   - log_requests       -> log-requests
   - forbidden_page     -> forbidden-page
   - sign_in_page       -> sign-in-page
   - secret             -> client-secret

#### **1.0.1 (April 8th, 2016)**

FIXES:
 * Fixed the refresh tokens for those provides whom do not use JWT tokens, Google Connect for example

#### **1.0.0 (April 8th, 2016)**

FEATURES
 * Added the /oauth/expiration controller to test for access token expiration
 * Added the /oauth/token as a helper method to display the access token

FIXES:
 * Fixed and cleaned up a few niggling issues

#### **1.0.0-rc6 (March 31th, 2016)**

FIXES:
 * Added a option to control the upstream TLS verification
 * Added in the x-forwarded-for headers rather than overwriting
 * Moved back to using the official coreos go-oidc rather than the hacked version

#### **1.0.0-rc5 (March 15th, 2016)**

FEATURES:

 * Added the realm access roles for keycloak, beforehand the user contect
   was only parses roles which were from client applications

BUGS:

 * Fixed the gitlab-ci build scripts
 * Fixed the custom forbidden page bug

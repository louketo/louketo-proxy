
#### **2.0.0**

FEATURES:
 * Adding the --skip-openid-provider-tls-verify option to bypass the TLS verification for Idp

FIXES:
 * Fixed the --headers and --tags command line options, had a typo on the mergeMaps method

BREAKING CHANGES:
 * The login handler by default has been switched off, you must enable for --enable-login-handler

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
 * Fixed the environment variable command line options, the IsSet in cli does not check enviroment
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
 * Cleaned up a lot of code base to make this simplier
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
